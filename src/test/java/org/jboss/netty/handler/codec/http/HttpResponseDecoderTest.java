/*
 * Copyright 2014 The Netty Project
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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

public class HttpResponseDecoderTest {

    @Test
    public void testWebSocketResponse() {
        byte[] data = ("HTTP/1.1 101 WebSocket Protocol Handshake\r\n" +
                       "Upgrade: WebSocket\r\n" +
                       "Connection: Upgrade\r\n" +
                       "Sec-WebSocket-Origin: http://localhost:8080\r\n" +
                       "Sec-WebSocket-Location: ws://localhost/some/path\r\n" +
                       "\r\n" +
                       "1234567812345678").getBytes();
        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpResponseDecoder());
        ch.offer(ChannelBuffers.wrappedBuffer(data));

        HttpResponse res = (HttpResponse) ch.poll();
        assertThat(res.getProtocolVersion(), sameInstance(HttpVersion.HTTP_1_1));
        assertThat(res.getStatus(), is(HttpResponseStatus.SWITCHING_PROTOCOLS));
        assertThat(res.getContent().readableBytes(), is(16));

        assertThat(ch.finish(), is(false));

        assertThat(ch.poll(), is(nullValue()));
    }

    // See https://github.com/netty/netty/issues/2173
    @Test
    public void testWebSocketResponseWithDataFollowing() {
        byte[] data = ("HTTP/1.1 101 WebSocket Protocol Handshake\r\n" +
                       "Upgrade: WebSocket\r\n" +
                       "Connection: Upgrade\r\n" +
                       "Sec-WebSocket-Origin: http://localhost:8080\r\n" +
                       "Sec-WebSocket-Location: ws://localhost/some/path\r\n" +
                       "\r\n" +
                       "1234567812345678EXTRA").getBytes(CharsetUtil.US_ASCII);

        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpResponseDecoder());
        ch.offer(ChannelBuffers.wrappedBuffer(data));

        HttpResponse res = (HttpResponse) ch.poll();
        assertThat(res.getProtocolVersion(), sameInstance(HttpVersion.HTTP_1_1));
        assertThat(res.getStatus(), is(HttpResponseStatus.SWITCHING_PROTOCOLS));
        assertThat(res.getContent().readableBytes(), is(16));

        assertThat(ch.finish(), is(true));

        assertEquals(ch.poll(), ChannelBuffers.wrappedBuffer("EXTRA".getBytes(CharsetUtil.US_ASCII)));
    }

    @Test
    public void testWebSocketResponseWithDataFollowing2() {
        byte[] data = ("HTTP/1.1 101 Switching Protocols\n" +
                       "Upgrade: websocket\n" +
                       "Connection: Upgrade\n" +
                       "Sec-WebSocket-Accept: fd6T8bTOMVN65WHXymeKp6WTWfA=\n\n" +
                       "EXTRA").getBytes(CharsetUtil.US_ASCII);

        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpResponseDecoder());
        ch.offer(ChannelBuffers.wrappedBuffer(data));

        HttpResponse res = (HttpResponse) ch.poll();
        assertThat(res.getProtocolVersion(), sameInstance(HttpVersion.HTTP_1_1));
        assertThat(res.getStatus(), is(HttpResponseStatus.SWITCHING_PROTOCOLS));
        assertThat(res.getContent().readableBytes(), is(0));

        assertThat(ch.finish(), is(true));

        assertEquals(ch.poll(), ChannelBuffers.wrappedBuffer("EXTRA".getBytes(CharsetUtil.US_ASCII)));
    }

    // Regression tests for the backport of upstream commit 07aa6b5938
    // ("Merge pull request from GHSA-wx5j-54mm-rqqq", netty 4.1.71.Final),
    // which closes CVE-2021-43797.

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

    private static void testHeaderNameStartsWithControlChar(int controlChar) {
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "HTTP/1.1 200 OK\r\n" +
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

    private static void testHeaderNameEndsWithControlChar(int controlChar) {
        ChannelBuffer buf = ChannelBuffers.dynamicBuffer();
        writeAscii(buf, "HTTP/1.1 200 OK\r\n" +
                "Host: netty.io\r\n" +
                "Transfer-Encoding");
        buf.writeByte(controlChar);
        writeAscii(buf, ": chunked\r\n\r\n");
        assertDecoderRejects(buf);
    }

    private static void writeAscii(ChannelBuffer buf, String s) {
        buf.writeBytes(s.getBytes(CharsetUtil.US_ASCII));
    }

    private static void assertDecoderRejects(ChannelBuffer buf) {
        DecoderEmbedder<Object> ch = new DecoderEmbedder<Object>(new HttpResponseDecoder());
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
