/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_INFO_H
#define GT86_PROJECTION_INFO_H
#include "rtsp_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_INFO_LIMIT 32768u
#define PROJECTION_INFO_DISPLAYS 2u
#define PROJECTION_INFO_HIDS 4u
#define PROJECTION_INFO_AUDIO 9u
#define PROJECTION_INFO_EXTENSIONS 8u
#define PROJECTION_INFO_ICONS 2u
enum projection_info_audio_type {
    PROJECTION_AUDIO_ANY, PROJECTION_AUDIO_COMPATIBILITY, PROJECTION_AUDIO_DEFAULT,
    PROJECTION_AUDIO_MEDIA, PROJECTION_AUDIO_TELEPHONY, PROJECTION_AUDIO_SPEECH,
    PROJECTION_AUDIO_ALERT
};
typedef struct projection_info_rect { uint32_t x,y,width,height; } projection_info_rect;
typedef struct projection_info_display {
    rtsp_slice uuid,initial_url;
    uint32_t type,width,height,width_mm,height_mm,max_fps,features,primary_input;
    projection_info_rect view,safe;
    uint8_t has_view,has_safe,draw_outside_safe;
} projection_info_display;
typedef struct projection_info_hid {
    rtsp_slice uuid,name,display_uuid,descriptor;
    uint16_t product_id,vendor_id; uint8_t country_code;
} projection_info_hid;
typedef struct projection_info_audio_format {
    uint32_t type,input_formats,output_formats;
    enum projection_info_audio_type audio_type;
} projection_info_audio_format;
typedef struct projection_info_latency {
    uint32_t type,input_micros,output_micros;
    enum projection_info_audio_type audio_type;
} projection_info_latency;
typedef struct projection_info_resource {
    uint32_t id,transfer_type,priority,take_constraint,borrow_constraint,unborrow_constraint;
} projection_info_resource;
typedef struct projection_info_icon { rtsp_slice data; uint32_t width,height; uint8_t prerendered; } projection_info_icon;
typedef struct projection_info_profile {
    rtsp_slice source_version,model,manufacturer,device_id,bluetooth_id,name,oem_label;
    uint64_t features,status_flags;
    uint8_t right_hand_drive,keep_alive_low_power,keep_alive_stats,hevc;
    uint8_t call_active,turn_by_turn_active;
    int32_t speech_mode; /* >=-1; -1 encoded as binary real, matching pinned LIVI. */
    projection_info_display displays[PROJECTION_INFO_DISPLAYS]; size_t display_count;
    projection_info_hid hids[PROJECTION_INFO_HIDS]; size_t hid_count;
    projection_info_audio_format audio[PROJECTION_INFO_AUDIO]; size_t audio_count;
    projection_info_latency latencies[PROJECTION_INFO_AUDIO]; size_t latency_count;
    projection_info_resource resources[2]; size_t resource_count;
    rtsp_slice extensions[PROJECTION_INFO_EXTENSIONS]; size_t extension_count;
    projection_info_icon icons[PROJECTION_INFO_ICONS]; size_t icon_count;
} projection_info_profile;
/* Pure bounded bplist00 capability encoder; no runtime discovery, default
 * feature mask, default identity/dimensions/HID/audio formats, provider or I/O.
 * Text is explicit printable ASCII (identity/name <=64, URL <=256); UUIDs are
 * canonical lowercase. Data/HID descriptors are opaque, not validated hardware
 * capabilities. Caller must provide ONLY implemented, currently available
 * features/resources. Structural validation does not certify their semantics.
 *
 * Root contains identity, flags, bluetoothIDs, modes, extendedFeatures,
 * displays and hidDevices; audio/latencies/icons/HEVC are opt-in. Screen type
 * 110 required when any display exists; optional second type111. Resource IDs
 * 1/2 must match declared screen/audio presence. No orphan/duplicate HID IDs,
 * displays, audio entries, latency entries, resources or extension names.
 * Display rectangles must be nonempty/contained. Format masks, feature flags,
 * arbitration and primary-input values require external backend validation.
 *
 * <=640 internal objects, <=32768 wire bytes. No heap; substantial bounded
 * stack scratch. Measurement: out=NULL, capacity=0 -> OK/required size.
 * Every failure leaves output untouched and written=0. Arguments/profile and
 * referenced data are immutable/disjoint during the call; no reentry/concurrency.
 * This is not a general-purpose plist graph encoder or CarPlay conformance test.
 */
int projection_info_encode(const projection_info_profile *,uint8_t *out,size_t capacity,size_t *written);
#ifdef __cplusplus
}
#endif
#endif
