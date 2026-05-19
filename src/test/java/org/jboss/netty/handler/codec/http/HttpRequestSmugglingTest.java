/*
 * Copyright 2026 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.jboss.netty.handler.codec.http;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.embedder.CodecEmbedderException;
import org.jboss.netty.handler.codec.embedder.DecoderEmbedder;
import org.jboss.netty.util.CharsetUtil;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Regression tests for backpatch.002, which closes:
 *
 * <ul>
 *   <li>CVE-2019-20445 - HTTP request smuggling via multiple Content-Length
 *       headers or Content-Length combined with Transfer-Encoding: chunked.
 *       Ported from upstream commit
 *       {@code 8494b046ec7e4f28dbd44bc699cc4c4c92251729} (netty 4.1.44).</li>
 *   <li>CVE-2020-7238 - HTTP request smuggling via non-SP/HTAB whitespace
 *       (file separator 0x1C-0x1F, raw LF, etc.) used as token separators
 *       in the initial line. Ported from upstream commit
 *       {@code 9ae782d632ff18f7c9e645c58458b3180d257ff3} (netty 4.1.46).
 *       The header-value side of the same upstream fix (rejecting VT between
 *       colon and value) already shipped in backpatch.001 as part of
 *       CVE-2021-43797's strict-OWS {@code findNonWhitespace} change; the
 *       regression test for that leg lives in
 *       {@link HttpRequestDecoderTest#testNonOwsWhitespaceBeforeHeaderValueRejected()}.</li>
 * </ul>
 */
public class HttpRequestSmugglingTest {

    // ---------------------------------------------------------------------
    // CVE-2019-20445
    // ---------------------------------------------------------------------

    @Test
    public void rejectsMultipleContentLengthHeaders() {
        // Two Content-Length headers with the same value - the trivial form
        // RFC 7230 section 3.3.2 specifically calls out as request smuggling.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "POST / HTTP/1.1\r\n" +
                "Host: target.example\r\n" +
                "Content-Length: 7\r\n" +
                "Content-Length: 7\r\n" +
                "\r\n" +
                "payload");
        assertDecoderRejects(buf);
    }

    @Test
    public void rejectsMultipleContentLengthHeadersDifferentValues() {
        // Two Content-Length headers with conflicting values - the classic
        // smuggling vector when an upstream proxy honors one and netty honors
        // the other.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "POST / HTTP/1.1\r\n" +
                "Host: target.example\r\n" +
                "Content-Length: 6\r\n" +
                "Content-Length: 5\r\n" +
                "\r\n" +
                "smug-x");
        assertDecoderRejects(buf);
    }

    @Test
    public void rejectsContentLengthWithTransferEncodingChunked() {
        // Per RFC 7230 section 3.3.3, when both Content-Length and
        // Transfer-Encoding: chunked are present, Transfer-Encoding overrides,
        // but the message SHOULD be treated as an error. We reject outright
        // on HTTP/1.1 to close the smuggling vector at the parser level.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "POST / HTTP/1.1\r\n" +
                "Host: target.example\r\n" +
                "Content-Length: 5\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "0\r\n\r\n");
        assertDecoderRejects(buf);
    }

    @Test
    public void rejectsContentLengthWithTransferEncodingChunkedOrderReversed() {
        // Same as above but headers reversed - the parser must catch both
        // orderings because we evaluate them at end-of-headers.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "POST / HTTP/1.1\r\n" +
                "Host: target.example\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "Content-Length: 5\r\n" +
                "\r\n" +
                "0\r\n\r\n");
        assertDecoderRejects(buf);
    }

    @Test
    public void acceptsSingleContentLength() {
        // Sanity: a well-formed single-Content-Length request still parses.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "POST / HTTP/1.1\r\n" +
                "Host: target.example\r\n" +
                "Content-Length: 5\r\n" +
                "\r\n" +
                "hello");
        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        ch.offer(buf);
        Object msg = ch.poll();
        assertTrue("expected HttpMessage, got " + msg, msg instanceof HttpMessage);
    }

    @Test
    public void acceptsTransferEncodingChunkedAlone() {
        // Sanity: well-formed chunked-without-Content-Length still parses.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "POST / HTTP/1.1\r\n" +
                "Host: target.example\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "0\r\n\r\n");
        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        ch.offer(buf);
        Object msg = ch.poll();
        assertTrue("expected HttpMessage, got " + msg, msg instanceof HttpMessage);
    }

    @Test
    public void allowsMultipleContentLengthOnHttp10() {
        // RFC 7230 section 3.3.2's MUST applies to HTTP/1.1. HTTP/1.0 has
        // weaker framing rules and we mirror upstream 4.x in leaving it alone.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "POST / HTTP/1.0\r\n" +
                "Host: target.example\r\n" +
                "Content-Length: 5\r\n" +
                "Content-Length: 5\r\n" +
                "\r\n" +
                "hello");
        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        ch.offer(buf);
        Object msg = ch.poll();
        assertTrue("expected HttpMessage, got " + msg, msg instanceof HttpMessage);
    }

    // ---------------------------------------------------------------------
    // CVE-2020-7238 - initial-line tightening. The header-value side ships
    // in HttpRequestDecoderTest from backpatch.001.
    // ---------------------------------------------------------------------

    @Test
    public void rejectsInitialLineWithFileSeparatorBetweenTokens() {
        // 0x1C (FS, file separator) sitting between "GET" and "/path".
        // Character.isWhitespace returns true for it, so the legacy
        // findNonWhitespace/findWhitespace pair treated it as a valid token
        // separator. findNonSPLenient rejects it: 0x1C is whitespace but
        // NOT SP-lenient (RFC 7230 section 3.5 restricts the relaxed set
        // to SP/HTAB/VT/FF/CR).
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        buf.writeByte('G');
        buf.writeByte('E');
        buf.writeByte('T');
        buf.writeByte(0x1C);
        writeAscii(buf, "/path HTTP/1.1\r\n\r\n");
        assertDecoderRejects(buf);
    }

    @Test
    public void rejectsInitialLineWithGroupSeparatorBetweenTokens() {
        // 0x1D (GS) - same shape as 0x1C; verifies the rest of the 0x1C-0x1F
        // band is rejected by findNonSPLenient.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        buf.writeByte('G');
        buf.writeByte('E');
        buf.writeByte('T');
        buf.writeByte(0x1D);
        writeAscii(buf, "/path HTTP/1.1\r\n\r\n");
        assertDecoderRejects(buf);
    }

    @Test
    public void rejectsInitialLineWithUnitSeparatorBetweenTokens() {
        // 0x1F (US) - completes coverage of the 0x1C-0x1F band.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        buf.writeByte('G');
        buf.writeByte('E');
        buf.writeByte('T');
        buf.writeByte(0x1F);
        writeAscii(buf, "/path HTTP/1.1\r\n\r\n");
        assertDecoderRejects(buf);
    }

    @Test
    public void rejectsInitialLineWithLoneLFBetweenTokens() {
        // 0x0A (raw LF without preceding CR) sitting between "GET" and
        // "/path". isWhitespace but not SP-lenient. A raw LF inside the
        // initial line is the line-folding/smuggling primitive.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        buf.writeByte('G');
        buf.writeByte('E');
        buf.writeByte('T');
        buf.writeByte(0x0A);
        writeAscii(buf, "/path HTTP/1.1\r\n\r\n");
        assertDecoderRejects(buf);
    }

    @Test
    public void acceptsInitialLineWithStandardSeparators() {
        // Sanity: a normal SP-separated request still parses.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "GET /path HTTP/1.1\r\n\r\n");
        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        ch.offer(buf);
        Object msg = ch.poll();
        assertTrue("expected HttpMessage, got " + msg, msg instanceof HttpMessage);
    }

    @Test
    public void acceptsInitialLineWithHorizontalTabSeparator() {
        // RFC 7230 section 3.5 says implementations MAY accept HTAB
        // between request-line tokens. Pinning this in place because
        // findNonSPLenient/findSPLenient explicitly count HTAB as
        // SP-lenient.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "GET\t/path\tHTTP/1.1\r\n\r\n");
        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        ch.offer(buf);
        Object msg = ch.poll();
        assertTrue("expected HttpMessage, got " + msg, msg instanceof HttpMessage);
    }

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    private static void writeAscii(ChannelBuffer buf, String s) {
        buf.writeBytes(s.getBytes(CharsetUtil.US_ASCII));
    }

    private static void assertDecoderRejects(ChannelBuffer buf) {
        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        try {
            ch.offer(buf);
            // If the failure surfaces at poll()/finish(), drain to force it.
            ch.poll();
            ch.finish();
            fail("expected CodecEmbedderException wrapping IllegalArgumentException, got none");
        } catch (CodecEmbedderException expected) {
            Throwable cause = expected.getCause();
            assertTrue("expected IllegalArgumentException cause, got " + cause,
                    cause instanceof IllegalArgumentException);
        }
    }
}
