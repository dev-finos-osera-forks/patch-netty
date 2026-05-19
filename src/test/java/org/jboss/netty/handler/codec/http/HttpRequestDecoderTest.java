/*
 * Copyright 2021 The Netty Project
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
 * Regression tests for the backport of upstream commit 07aa6b5938
 * ("Merge pull request from GHSA-wx5j-54mm-rqqq", netty 4.1.71.Final),
 * which closes CVE-2021-43797 — HTTP request smuggling via control
 * characters silently stripped from header names.
 *
 * Ported from 4.x HttpRequestDecoderTest. The 3.x decoder embedder reports
 * decoder failures by throwing a CodecEmbedderException wrapping the
 * underlying IllegalArgumentException, rather than via the 4.x
 * DecoderResult mechanism.
 */
public class HttpRequestDecoderTest {

    @Test
    public void testHeaderNameStartsWithControlChar1c() {
        testHeaderNameStartsWithControlChar(0x1c);
    }

    @Test
    public void testHeaderNameStartsWithControlChar1d() {
        testHeaderNameStartsWithControlChar(0x1d);
    }

    @Test
    public void testHeaderNameStartsWithControlChar1e() {
        testHeaderNameStartsWithControlChar(0x1e);
    }

    @Test
    public void testHeaderNameStartsWithControlChar1f() {
        testHeaderNameStartsWithControlChar(0x1f);
    }

    @Test
    public void testHeaderNameStartsWithControlChar0c() {
        testHeaderNameStartsWithControlChar(0x0c);
    }

    @Test
    public void testHeaderNameStartsWithNul() {
        testHeaderNameStartsWithControlChar(0x00);
    }

    private static void testHeaderNameStartsWithControlChar(int controlChar) {
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "GET /some/path HTTP/1.1\r\n" +
                "Host: netty.io\r\n");
        buf.writeByte(controlChar);
        writeAscii(buf, "Transfer-Encoding: chunked\r\n\r\n");
        assertDecoderRejects(buf);
    }

    @Test
    public void testHeaderNameEndsWithControlChar1c() {
        testHeaderNameEndsWithControlChar(0x1c);
    }

    @Test
    public void testHeaderNameEndsWithControlChar1d() {
        testHeaderNameEndsWithControlChar(0x1d);
    }

    @Test
    public void testHeaderNameEndsWithControlChar1e() {
        testHeaderNameEndsWithControlChar(0x1e);
    }

    @Test
    public void testHeaderNameEndsWithControlChar1f() {
        testHeaderNameEndsWithControlChar(0x1f);
    }

    @Test
    public void testHeaderNameEndsWithControlChar0c() {
        testHeaderNameEndsWithControlChar(0x0c);
    }

    @Test
    public void testHeaderNameEndsWithNul() {
        testHeaderNameEndsWithControlChar(0x00);
    }

    private static void testHeaderNameEndsWithControlChar(int controlChar) {
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "GET /some/path HTTP/1.1\r\n" +
                "Host: netty.io\r\n" +
                "Transfer-Encoding");
        buf.writeByte(controlChar);
        writeAscii(buf, ": chunked\r\n\r\n");
        assertDecoderRejects(buf);
    }

    @Test
    public void testNonOwsWhitespaceBeforeHeaderValueRejected() {
        // OWS is SP (0x20) or HTAB (0x09) only. A vertical tab (0x0B) between
        // the colon and the value would be silently skipped by the legacy
        // parser (Character.isWhitespace(0x0B) is true) — exactly the gap
        // CVE-2021-43797 exploits. The hardened parser must reject it.
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "POST / HTTP/1.1\r\n" +
                "Host: target.com\r\n" +
                "Transfer-Encoding:");
        buf.writeByte(0x0B);
        writeAscii(buf, "chunked\r\n\r\n");
        assertDecoderRejects(buf);
    }

    private static void writeAscii(ChannelBuffer buf, String s) {
        buf.writeBytes(s.getBytes(CharsetUtil.US_ASCII));
    }

    private static void assertDecoderRejects(ChannelBuffer buf) {
        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpRequestDecoder());
        try {
            ch.offer(buf);
            // If the failure surfaces at poll() time, drain to force it.
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
