//! mediasoup `rtpParameters` builders for plain-RTP producers.
//! Payload type and SSRC must match the ffmpeg RTP muxer exactly —
//! that pairing is what makes the SFU recognize our packets.

use crate::RtpDest;
use serde_json::{json, Value};

pub fn video_vp8(dest: &RtpDest, mid: &str) -> Value {
    json!({
        "mid": mid,
        "codecs": [{
            "mimeType": "video/VP8",
            "payloadType": dest.payload_type,
            "clockRate": 90000,
            "rtcpFeedback": [
                { "type": "nack" },
                { "type": "nack", "parameter": "pli" },
                { "type": "ccm", "parameter": "fir" },
                { "type": "goog-remb" }
            ]
        }],
        "headerExtensions": [],
        "encodings": [{ "ssrc": dest.ssrc }],
        "rtcp": { "cname": "laira-native", "reducedSize": true, "mux": true }
    })
}

pub fn video_h264(dest: &RtpDest, mid: &str) -> Value {
    json!({
        "mid": mid,
        "codecs": [{
            "mimeType": "video/H264",
            "payloadType": dest.payload_type,
            "clockRate": 90000,
            "parameters": {
                "packetization-mode": 1,
                "profile-level-id": "42e01f",
                "level-asymmetry-allowed": 1
            },
            "rtcpFeedback": [
                { "type": "nack" },
                { "type": "nack", "parameter": "pli" },
                { "type": "ccm", "parameter": "fir" },
                { "type": "goog-remb" }
            ]
        }],
        "headerExtensions": [],
        "encodings": [{ "ssrc": dest.ssrc }],
        "rtcp": { "cname": "laira-native", "reducedSize": true, "mux": true }
    })
}

pub fn audio_opus(dest: &RtpDest, mid: &str) -> Value {
    json!({
        "mid": mid,
        "codecs": [{
            "mimeType": "audio/opus",
            "payloadType": dest.payload_type,
            "clockRate": 48000,
            "channels": 2,
            "rtcpFeedback": [{ "type": "transport-cc" }]
        }],
        "headerExtensions": [],
        "encodings": [{ "ssrc": dest.ssrc }],
        "rtcp": { "cname": "laira-native", "reducedSize": true, "mux": true }
    })
}
