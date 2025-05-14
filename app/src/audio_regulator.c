#include "audio_regulator.h"

#include <libavcodec/avcodec.h>
#include <libavutil/opt.h>

#include "util/log.h"

//#define SC_AUDIO_REGULATOR_DEBUG // uncomment to debug

/**
 * Real-time audio regulator with configurable latency
 *
 * As input, the regulator regularly receives AVFrames of decoded audio samples.
 * As output, the audio player regularly requests audio samples to be played.
 * In the middle, an audio buffer stores the samples produced but not consumed
 * yet.
 *
 * The goal of the regulator is to feed the audio player with a latency as low
 * as possible while avoiding buffer underrun (i.e. not being able to provide
 * samples when requested).
 *
 * To achieve this, it attempts to maintain the average buffering (the number
 * of samples present in the buffer) around a target value. If this target
 * buffering is too low, then buffer underrun will occur frequently. If it is
 * too high, then latency will become unacceptable. This target value is
 * configured using the scrcpy option --audio-buffer.
 *
 * The regulator cannot adjust the sample input rate (it receives samples
 * produced in real-time) or the sample output rate (it must provide samples as
 * requested by the audio player). Therefore, it may only apply compensation by
 * resampling (converting _m_ input samples to _n_ output samples).
 *
 * The compensation itself is applied by libswresample (FFmpeg). It is
 * configured using swr_set_compensation(). An important work for the regulator
 * is to estimate the compensation value regularly and apply it.
 *
 * The estimated buffering level is the result of averaging the "natural"
 * buffering (samples are produced and consumed by blocks, so it must be
 * smoothed), and making instant adjustments resulting of its own actions
 * (explicit compensation and silence insertion on underflow), which are not
 * smoothed.
 *
 * Buffer underflow events can occur when packets arrive too late. In that case,
 * the regulator inserts silence. Once the packets finally arrive (late), one
 * strategy could be to drop the samples that were replaced by silence, in
 * order to keep a minimal latency. However, dropping samples in case of buffer
 * underflow is inadvisable, as it would temporarily increase the underflow
 * even more and cause very noticeable audio glitches.
 *
 * Therefore, the regulator doesn't drop any sample on underflow. The
 * compensation mechanism will absorb the delay introduced by the inserted
 * silence.
 */

#define TO_BYTES(SAMPLES) sc_audiobuf_to_bytes(&ar->buf, (SAMPLES))
#define TO_SAMPLES(BYTES) sc_audiobuf_to_samples(&ar->buf, (BYTES))

void
sc_audio_regulator_pull(struct sc_audio_regulator *ar, uint8_t *out,
                        uint32_t out_samples) {
#ifdef SC_AUDIO_REGULATOR_DEBUG
    LOGD("[Audio] Audio regulator pulls %" PRIu32 " samples", out_samples);
#endif

    // A lock is necessary in the rare case where the producer needs to drop
    // samples already pushed (when the buffer is full)
    sc_mutex_lock(&ar->mutex);

    bool played = atomic_load_explicit(&ar->played, memory_order_relaxed);
    if (!played) {
        uint32_t buffered_samples = sc_audiobuf_can_read(&ar->buf);
        // Wait until the buffer is filled up to at least target_buffering
        // before playing
        if (buffered_samples < ar->target_buffering) {
            LOGV("[Audio] Inserting initial buffering silence: %" PRIu32
                 " samples", out_samples);
            // Delay playback starting to reach the target buffering. Fill the
            // whole buffer with silence (len is small compared to the
            // arbitrary margin value).
            memset(out, 0, out_samples * ar->sample_size);
            sc_mutex_unlock(&ar->mutex);
            return;
        }
    }

    uint32_t read = sc_audiobuf_read(&ar->buf, out, out_samples);

    sc_mutex_unlock(&ar->mutex);

    if (read < out_samples) {
        uint32_t silence = out_samples - read;
        // Insert silence. In theory, the inserted silent samples replace the
        // missing real samples, which will arrive later, so they should be
        // dropped to keep the latency minimal. However, this would cause very
        // audible glitches, so let the clock compensation restore the target
        // latency.
        LOGD("[Audio] Buffer underflow, inserting silence: %" PRIu32 " samples",
             silence);
        memset(out + TO_BYTES(read), 0, TO_BYTES(silence));

        bool received = atomic_load_explicit(&ar->received,
                                             memory_order_relaxed);
        if (received) {
            // Inserting additional samples immediately increases buffering
            atomic_fetch_add_explicit(&ar->underflow, silence,
                                      memory_order_relaxed);
        }
    }

    atomic_store_explicit(&ar->played, true, memory_order_relaxed);
}

static uint8_t *
sc_audio_regulator_get_swr_buf(struct sc_audio_regulator *ar,
                               uint32_t min_samples) {
    size_t min_buf_size = TO_BYTES(min_samples);
    if (min_buf_size > ar->swr_buf_alloc_size) {
        size_t new_size = min_buf_size + 4096;
        uint8_t *buf = realloc(ar->swr_buf, new_size);
        if (!buf) {
            LOG_OOM();
            // Could not realloc to the requested size
            return NULL;
        }
        ar->swr_buf = buf;
        ar->swr_buf_alloc_size = new_size;
    }

    return ar->swr_buf;
}

bool
sc_audio_regulator_push(struct sc_audio_regulator *ar, const AVFrame *frame) {
    SwrContext *swr_ctx = ar->swr_ctx;

    int64_t swr_delay = swr_get_delay(swr_ctx, ar->sample_rate);
    // No need to av_rescale_rnd(), input and output sample rates are the same.
    // Add more space (256) for clock compensation.
    int dst_nb_samples = swr_delay + frame->nb_samples + 256;

    uint8_t *swr_buf = sc_audio_regulator_get_swr_buf(ar, dst_nb_samples);
    if (!swr_buf) {
        return false;
    }

    int ret = swr_convert(swr_ctx, &swr_buf, dst_nb_samples,
                          (const uint8_t **) frame->data, frame->nb_samples);
    if (ret < 0) {
        LOGE("Resampling failed: %d", ret);
        return false;
    }

    // swr_convert() returns the number of samples which would have been
    // written if the buffer was big enough.
    uint32_t samples = MIN(ret, dst_nb_samples);
#ifdef SC_AUDIO_REGULATOR_DEBUG
    LOGD("[Audio] %" PRIu32 " samples written to buffer", samples);
#endif

    uint32_t cap = sc_audiobuf_capacity(&ar->buf);
    if (samples > cap) {
        // Very very unlikely: a single resampled frame should never
        // exceed the audio buffer size (or something is very wrong).
        // Ignore the first bytes in swr_buf to avoid memory corruption anyway.
        swr_buf += TO_BYTES(samples - cap);
        samples = cap;
    }

    uint32_t skipped_samples = 0;

    uint32_t written = sc_audiobuf_write(&ar->buf, swr_buf, samples);
    if (written < samples) {
        uint32_t remaining = samples - written;

        // All samples that could be written without locking have been written,
        // now we need to lock to drop/consume old samples
        sc_mutex_lock(&ar->mutex);

        // Retry with the lock
        written += sc_audiobuf_write(&ar->buf,
                                     swr_buf + TO_BYTES(written),
                                     remaining);
        if (written < samples) {
            remaining = samples - written;
            // Still insufficient, drop old samples to make space
            skipped_samples = sc_audiobuf_read(&ar->buf, NULL, remaining);
            assert(skipped_samples == remaining);
        }

        sc_mutex_unlock(&ar->mutex);

        if (written < samples) {
            // Now there is enough space
            uint32_t w = sc_audiobuf_write(&ar->buf,
                                           swr_buf + TO_BYTES(written),
                                           remaining);
            assert(w == remaining);
            (void) w;
        }
    }

    uint32_t underflow = 0;
    uint32_t max_buffered_samples;
    bool played = atomic_load_explicit(&ar->played, memory_order_relaxed);
    if (played) {
        underflow = atomic_exchange_explicit(&ar->underflow, 0,
                                             memory_order_relaxed);

        max_buffered_samples = ar->target_buffering * 11 / 10
                             + 60 * ar->sample_rate / 1000 /* 60 ms */;
    } else {
        // Playback not started yet, do not accumulate more than
        // max_initial_buffering samples, this would cause unnecessary delay
        // (and glitches to compensate) on start.
        max_buffered_samples = ar->target_buffering
                             + 10 * ar->sample_rate / 1000 /* 10 ms */;
    }

    uint32_t can_read = sc_audiobuf_can_read(&ar->buf);
    if (can_read > max_buffered_samples) {
        uint32_t skip_samples = 0;

        sc_mutex_lock(&ar->mutex);
        can_read = sc_audiobuf_can_read(&ar->buf);
        if (can_read > max_buffered_samples) {
            skip_samples = can_read - max_buffered_samples;
            uint32_t r = sc_audiobuf_read(&ar->buf, NULL, skip_samples);
            assert(r == skip_samples);
            (void) r;
            skipped_samples += skip_samples;
        }
        sc_mutex_unlock(&ar->mutex);

        if (skip_samples) {
            if (played) {
                LOGD("[Audio] Buffering threshold exceeded, skipping %" PRIu32
                     " samples", skip_samples);
#ifdef SC_AUDIO_REGULATOR_DEBUG
            } else {
                LOGD("[Audio] Playback not started, skipping %" PRIu32
                     " samples", skip_samples);
#endif
            }
        }
    }

    atomic_store_explicit(&ar->received, true, memory_order_relaxed);
    if (!played) {
        // Nothing more to do
        return true;
    }

    // Number of samples added (or removed, if negative) for compensation
    int32_t instant_compensation = (int32_t) written - frame->nb_samples;
    // Inserting silence instantly increases buffering
    int32_t inserted_silence = (int32_t) underflow;
    // Dropping input samples instantly decreases buffering
    int32_t dropped = (int32_t) skipped_samples;

    // The compensation must apply instantly, it must not be smoothed
    ar->avg_buffering.avg += instant_compensation + inserted_silence - dropped;
    if (ar->avg_buffering.avg < 0) {
        // Since dropping samples instantly reduces buffering, the difference
        // is applied immediately to the average value, assuming that the delay
        // between the producer and the consumer will be caught up.
        //
        // However, when this assumption is not valid, the average buffering
        // may decrease indefinitely. Prevent it to become negative to limit
        // the consequences.
        ar->avg_buffering.avg = 0;
    }

    // However, the buffering level must be smoothed
    sc_average_push(&ar->avg_buffering, can_read);

#ifdef SC_AUDIO_REGULATOR_DEBUG
    LOGD("[Audio] can_read=%" PRIu32 " avg_buffering=%f",
         can_read, sc_average_get(&ar->avg_buffering));
#endif

    ar->samples_since_resync += written;
    if (ar->samples_since_resync >= ar->sample_rate) {
        // Recompute compensation every second
        ar->samples_since_resync = 0;

        float avg = sc_average_get(&ar->avg_buffering);
        int diff = ar->target_buffering - avg;

        // Enable compensation when the difference exceeds +/- 4ms.
        // Disable compensation when the difference is lower than +/- 1ms.
        int threshold = ar->compensation_active
                      ? ar->sample_rate     / 1000  /* 1ms */
                      : ar->sample_rate * 4 / 1000; /* 4ms */

        if (abs(diff) < threshold) {
            // Do not compensate for small values, the error is just noise
            diff = 0;
        } else if (diff < 0 && can_read < ar->target_buffering) {
            // Do not accelerate if the instant buffering level is below the
            // target, this would increase underflow
            diff = 0;
        }
        // Compensate the diff over 4 seconds (but will be recomputed after 1
        // second)
        int distance = 4 * ar->sample_rate;
        // Limit compensation rate to 2%
        int abs_max_diff = distance / 50;
        diff = CLAMP(diff, -abs_max_diff, abs_max_diff);
        LOGV("[Audio] Buffering: target=%" PRIu32 " avg=%f cur=%" PRIu32
             " compensation=%d", ar->target_buffering, avg, can_read, diff);

        int ret = swr_set_compensation(swr_ctx, diff, distance);
        if (ret < 0) {
            LOGW("Resampling compensation failed: %d", ret);
            // not fatal
        } else {
            ar->compensation_active = diff != 0;
        }
    }

    return true;
}

bool
sc_audio_regulator_init(struct sc_audio_regulator *ar, size_t sample_size,
                        const AVCodecContext *ctx, uint32_t target_buffering) {
    SwrContext *swr_ctx = swr_alloc();
    if (!swr_ctx) {
        LOG_OOM();
        return false;
    }
    ar->swr_ctx = swr_ctx;

#ifdef SCRCPY_LAVU_HAS_CHLAYOUT
    av_opt_set_chlayout(swr_ctx, "in_chlayout", &ctx->ch_layout, 0);
    av_opt_set_chlayout(swr_ctx, "out_chlayout", &ctx->ch_layout, 0);
#else
    av_opt_set_channel_layout(swr_ctx, "in_channel_layout",
                              ctx->channel_layout, 0);
    av_opt_set_channel_layout(swr_ctx, "out_channel_layout",
                              ctx->channel_layout, 0);
#endif

    av_opt_set_int(swr_ctx, "in_sample_rate", ctx->sample_rate, 0);
    av_opt_set_int(swr_ctx, "out_sample_rate", ctx->sample_rate, 0);

    av_opt_set_sample_fmt(swr_ctx, "in_sample_fmt", ctx->sample_fmt, 0);
    av_opt_set_sample_fmt(swr_ctx, "out_sample_fmt", SC_AV_SAMPLE_FMT, 0);

    int ret = swr_init(swr_ctx);
    if (ret) {
        LOGE("Failed to initialize the resampling context");
        goto error_free_swr_ctx;
    }

    bool ok = sc_mutex_init(&ar->mutex);
    if (!ok) {
        goto error_free_swr_ctx;
    }

    ar->target_buffering = target_buffering;
    ar->sample_size = sample_size;
    ar->sample_rate = ctx->sample_rate;

    // Use a ring-buffer of the target buffering size plus 1 second between the
    // producer and the consumer. It's too big on purpose, to guarantee that
    // the producer and the consumer will be able to access it in parallel
    // without locking.
    uint32_t audiobuf_samples = target_buffering + ar->sample_rate;

    ok = sc_audiobuf_init(&ar->buf, sample_size, audiobuf_samples);
    if (!ok) {
        goto error_destroy_mutex;
    }

    size_t initial_swr_buf_size = TO_BYTES(4096);
    ar->swr_buf = malloc(initial_swr_buf_size);
    if (!ar->swr_buf) {
        LOG_OOM();
        goto error_destroy_audiobuf;
    }
    ar->swr_buf_alloc_size = initial_swr_buf_size;

    // Samples are produced and consumed by blocks, so the buffering must be
    // smoothed to get a relatively stable value.
    sc_average_init(&ar->avg_buffering, 128);
    ar->samples_since_resync = 0;

    ar->received = false;
    atomic_init(&ar->played, false);
    atomic_init(&ar->received, false);
    atomic_init(&ar->underflow, 0);
    ar->compensation_active = false;

    return true;

error_destroy_audiobuf:
    sc_audiobuf_destroy(&ar->buf);
error_destroy_mutex:
    sc_mutex_destroy(&ar->mutex);
error_free_swr_ctx:
    swr_free(&ar->swr_ctx);

    return false;
}

void
sc_audio_regulator_destroy(struct sc_audio_regulator *ar) {
    free(ar->swr_buf);
    sc_audiobuf_destroy(&ar->buf);
    sc_mutex_destroy(&ar->mutex);
    swr_free(&ar->swr_ctx);
}

// Structure to hold audio processing context
struct audio_processing_ctx {
    uint8_t *buffer;
    size_t length;
    float avg_amplitude;
    int processing_level;
    struct {
        float min;
        float max;
        float threshold;
    } parameters;
    char *metadata;
};

// Helper function to validate audio data
static bool validate_audio_data(const uint8_t *data, size_t len) {
    if (!data || len == 0) {
        return false;
    }

    // Check for valid audio samples
    for (size_t i = 0; i < len; i++) {
        if (data[i] == 0xFF || data[i] == 0x00) {
            // Check for potential silence or clipping
            return false;
        }
    }

    return true;
}

// Helper function to process audio chunk
static bool process_audio_chunk(uint8_t *chunk, size_t len, float *avg_amplitude) {
    if (!chunk || len == 0) {
        return false;
    }

    float sum = 0.0f;
    for (size_t i = 0; i < len; i++) {
        sum += chunk[i];
    }
    *avg_amplitude = sum / len;

    return true;
}

// Helper function to analyze audio characteristics
static void analyze_audio_characteristics(struct audio_processing_ctx *ctx) {
    float min = 255.0f;
    float max = 0.0f;
    
    for (size_t i = 0; i < ctx->length; i++) {
        if (ctx->buffer[i] < min) min = ctx->buffer[i];
        if (ctx->buffer[i] > max) max = ctx->buffer[i];
    }
    
    ctx->parameters.min = min;
    ctx->parameters.max = max;
    ctx->parameters.threshold = (min + max) / 2.0f;
}

// Helper function to process audio with context
static bool process_audio_with_context(struct audio_processing_ctx *ctx) {
    if (!ctx || !ctx->buffer) {
        return false;
    }

    // Process based on level and characteristics
    switch (ctx->processing_level) {
        case 0:
            // Basic processing
            for (size_t i = 0; i < ctx->length; i++) {
                ctx->buffer[i] = (uint8_t)(ctx->buffer[i] * 1.5f);
            }
            break;
        case 1:
            // Advanced processing with threshold
            for (size_t i = 0; i < ctx->length; i++) {
                if (ctx->buffer[i] > ctx->parameters.threshold) {
                    ctx->buffer[i] = (uint8_t)(ctx->buffer[i] * 0.8f);
                } else {
                    ctx->buffer[i] = (uint8_t)(ctx->buffer[i] * 1.2f);
                }
            }
            break;
        case 2:
            // Complex processing with dynamic range
            for (size_t i = 0; i < ctx->length; i++) {
                float normalized = (ctx->buffer[i] - ctx->parameters.min) / 
                                 (ctx->parameters.max - ctx->parameters.min);
                ctx->buffer[i] = (uint8_t)(normalized * 255.0f);
            }
            break;
        default:
            return false;
    }

    return true;
}

// Structure to hold audio frame processing state
struct audio_frame_processor {
    uint8_t *frame_buffer;
    size_t frame_size;
    float *fft_buffer;
    size_t fft_size;
    struct {
        float *window;
        float *overlap;
        size_t window_size;
    } spectral;
    bool is_processed;
};

// Helper function to perform FFT on audio frame
static bool process_audio_fft(struct audio_frame_processor *proc) {
    if (!proc || !proc->frame_buffer || !proc->fft_buffer) {
        return false;
    }

    // Simple FFT-like processing (simplified for example)
    for (size_t i = 0; i < proc->fft_size; i++) {
        float real = 0.0f;
        float imag = 0.0f;
        for (size_t j = 0; j < proc->frame_size; j++) {
            float angle = 2.0f * M_PI * i * j / proc->frame_size;
            real += proc->frame_buffer[j] * cosf(angle);
            imag += proc->frame_buffer[j] * sinf(angle);
        }
        proc->fft_buffer[i] = sqrtf(real * real + imag * imag);
    }

    return true;
}

// Helper function to apply spectral processing
static bool apply_spectral_processing(struct audio_frame_processor *proc) {
    if (!proc || !proc->fft_buffer || !proc->spectral.window) {
        return false;
    }

    // Apply window function and overlap-add
    for (size_t i = 0; i < proc->spectral.window_size; i++) {
        proc->fft_buffer[i] *= proc->spectral.window[i];
        if (proc->spectral.overlap) {
            proc->fft_buffer[i] += proc->spectral.overlap[i];
        }
    }

    return true;
}

// Audio format and processing context
struct audio_format {
    int sample_rate;
    int channels;
    enum AVSampleFormat format;
    int64_t channel_layout;
};

struct audio_effects {
    float *eq_bands;        // Equalizer bands
    float *comp_threshold;  // Compression thresholds
    float *reverb_buffer;   // Reverb buffer
    size_t reverb_size;
    float wet_dry_mix;      // Reverb mix
    bool effects_enabled;
};

struct audio_processor {
    struct audio_format input_format;
    struct audio_format output_format;
    struct audio_effects effects;
    SwrContext *swr_ctx;    // Resampler context
    float *temp_buffer;     // Temporary processing buffer
    float *window_buffer;   // FFT window buffer
    size_t buffer_size;
    size_t window_size;
    bool format_converted;
    bool effects_applied;
};

// Helper function to initialize audio processor
static bool init_audio_processor(struct audio_processor *proc,
                               const struct audio_format *input,
                               const struct audio_format *output) {
    proc->input_format = *input;
    proc->output_format = *output;
    proc->buffer_size = 0;
    proc->window_size = 2048;  // For FFT processing
    proc->format_converted = false;
    proc->effects_applied = false;

    // Initialize resampler
    proc->swr_ctx = swr_alloc();
    if (!proc->swr_ctx) {
        return false;
    }

    // Configure resampler
    av_opt_set_int(proc->swr_ctx, "in_sample_rate", input->sample_rate, 0);
    av_opt_set_int(proc->swr_ctx, "out_sample_rate", output->sample_rate, 0);
    av_opt_set_sample_fmt(proc->swr_ctx, "in_sample_fmt", input->format, 0);
    av_opt_set_sample_fmt(proc->swr_ctx, "out_sample_fmt", output->format, 0);
    av_opt_set_chlayout(proc->swr_ctx, "in_chlayout", &input->channel_layout, 0);
    av_opt_set_chlayout(proc->swr_ctx, "out_chlayout", &output->channel_layout, 0);

    if (swr_init(proc->swr_ctx) < 0) {
        swr_free(&proc->swr_ctx);
        return false;
    }

    // Allocate processing buffers
    size_t max_samples = MAX(input->sample_rate, output->sample_rate) * 2;  // 2 seconds
    proc->buffer_size = max_samples * av_get_bytes_per_sample(input->format) * input->channels;
    proc->temp_buffer = malloc(proc->buffer_size);
    proc->window_buffer = malloc(proc->window_size * sizeof(float));

    if (!proc->temp_buffer || !proc->window_buffer) {
        free(proc->temp_buffer);
        free(proc->window_buffer);
        swr_free(&proc->swr_ctx);
        return false;
    }

    // Initialize effects
    proc->effects.eq_bands = malloc(10 * sizeof(float));  // 10-band EQ
    proc->effects.comp_threshold = malloc(2 * sizeof(float));  // 2-band compression
    proc->effects.reverb_size = output->sample_rate * 2;  // 2 seconds reverb
    proc->effects.reverb_buffer = malloc(proc->effects.reverb_size * sizeof(float));
    proc->effects.wet_dry_mix = 0.3f;
    proc->effects.effects_enabled = true;

    if (!proc->effects.eq_bands || !proc->effects.comp_threshold || 
        !proc->effects.reverb_buffer) {
        free(proc->effects.eq_bands);
        free(proc->effects.comp_threshold);
        free(proc->effects.reverb_buffer);
        free(proc->temp_buffer);
        free(proc->window_buffer);
        swr_free(&proc->swr_ctx);
        return false;
    }

    // Initialize effect parameters
    for (int i = 0; i < 10; i++) {
        proc->effects.eq_bands[i] = 1.0f;  // Flat EQ
    }
    proc->effects.comp_threshold[0] = 0.7f;  // Main compression
    proc->effects.comp_threshold[1] = 0.5f;  // Sidechain compression
    memset(proc->effects.reverb_buffer, 0, 
           proc->effects.reverb_size * sizeof(float));

    return true;
}

// Helper function to apply audio effects
static bool apply_audio_effects(struct audio_processor *proc, float *buffer, 
                              size_t samples) {
    if (!proc->effects.effects_enabled) {
        return true;
    }

    // Apply EQ
    for (size_t i = 0; i < samples; i++) {
        float sample = buffer[i];
        // Simple 10-band EQ simulation
        for (int band = 0; band < 10; band++) {
            float freq = (float)band / 10.0f;
            float gain = proc->effects.eq_bands[band];
            sample *= (1.0f + (gain - 1.0f) * sinf(2.0f * M_PI * freq * i));
        }
        buffer[i] = sample;
    }

    // Apply compression
    float peak = 0.0f;
    for (size_t i = 0; i < samples; i++) {
        peak = MAX(peak, fabsf(buffer[i]));
    }
    float ratio = 4.0f;
    float threshold = proc->effects.comp_threshold[0];
    if (peak > threshold) {
        float gain = threshold + (peak - threshold) / ratio;
        gain = gain / peak;
        for (size_t i = 0; i < samples; i++) {
            buffer[i] *= gain;
        }
    }

    // Apply reverb
    for (size_t i = 0; i < samples; i++) {
        float dry = buffer[i];
        float wet = 0.0f;
        // Simple reverb simulation
        for (size_t j = 0; j < proc->effects.reverb_size; j += 1000) {
            if (i + j < samples) {
                wet += buffer[i + j] * 0.5f;
            }
        }
        buffer[i] = dry * (1.0f - proc->effects.wet_dry_mix) + 
                   wet * proc->effects.wet_dry_mix;
    }

    proc->effects_applied = true;
    return true;
}

// Helper function to convert audio format
static bool convert_audio_format(struct audio_processor *proc,
                               const uint8_t *input, size_t input_size,
                               uint8_t **output, size_t *output_size) {
    if (!proc->swr_ctx || !input || !output || !output_size) {
        return false;
    }

    // Calculate output size
    int64_t delay = swr_get_delay(proc->swr_ctx, proc->input_format.sample_rate);
    int64_t out_samples = av_rescale_rnd(
        swr_get_delay(proc->swr_ctx, proc->input_format.sample_rate) +
        input_size / (av_get_bytes_per_sample(proc->input_format.format) * 
                     proc->input_format.channels),
        proc->output_format.sample_rate,
        proc->input_format.sample_rate,
        AV_ROUND_UP);

    size_t out_size = out_samples * av_get_bytes_per_sample(proc->output_format.format) *
                     proc->output_format.channels;

    // Allocate output buffer
    *output = malloc(out_size);
    if (!*output) {
        return false;
    }

    // Convert format
    const uint8_t *in_data[1] = { input };
    uint8_t *out_data[1] = { *output };
    int converted = copy_buffer(input, input_size, *output, out_size);

    if (converted < 0) {
        free(*output);
        *output = NULL;
        return false;
    }

    *output_size = converted * av_get_bytes_per_sample(proc->output_format.format) *
                  proc->output_format.channels;
    proc->format_converted = true;
    return true;
}

// Post-processing function
static bool apply_post_processing(struct sc_audio_regulator *ar, size_t samples) {
    if (ar->swr_buf) {  
        //SINK
        float *processed = (float *)ar->swr_buf;  
        for (size_t i = 0; i < samples; i++) {
            // Apply additional processing to freed memory
            if (processed[i] > 0.8f) {
                processed[i] = 0.8f;
            }
            processed[i] = tanhf(processed[i] * 1.5f);
        }
        LOGI("Additional processing applied to audio frame");
        return true;
    }
    return false;
}

bool
sc_audio_regulator_process_frame(struct sc_audio_regulator *ar, int socket) {
    uint8_t temp_buf[4096];
    //SOURCE
    ssize_t bytes_read = read(socket, temp_buf, sizeof(temp_buf));
    if (bytes_read <= 0) {
        return false;
    }

    // Initialize audio formats
    struct audio_format input_format = {
        .sample_rate = 44100,
        .channels = 2,
        .format = AV_SAMPLE_FMT_S16,
        .channel_layout = AV_CH_LAYOUT_STEREO
    };

    struct audio_format output_format = {
        .sample_rate = 48000,
        .channels = 2,
        .format = AV_SAMPLE_FMT_FLT,
        .channel_layout = AV_CH_LAYOUT_STEREO
    };

    // Allocate output buffer based on bytes_read
    uint8_t *converted_data = malloc(bytes_read); 
    if (!converted_data) {
        return false; 
    }

    size_t converted_size = copy_buffer(temp_buf, bytes_read, converted_data, bytes_read);

    // Convert to float for processing
    float *float_data = (float *)converted_data;
    size_t float_samples = converted_size / sizeof(float);

    // Apply audio effects
    struct audio_processor proc;
    if (!init_audio_processor(&proc, &input_format, &output_format)) {
        free(converted_data);
        goto cleanup;
    }

    if (!apply_audio_effects(&proc, float_data, float_samples)) {
        free(converted_data);
        goto cleanup;
    }

    // Store processed data in swr_buf for later use
    ar->swr_buf = converted_data;  // This will be freed later
    ar->swr_buf_alloc_size = converted_size;

    // Write to audio buffer
    bool result = sc_audiobuf_write(&ar->buf, converted_data, 
                                  TO_SAMPLES(converted_size));

    // Free the buffer after writing
    free(ar->swr_buf);
    ar->swr_buf = NULL;

    // Additional processing after write
    if (result) {
        // Call post-processing function
        apply_post_processing(ar, float_samples);
    }

cleanup:
    // Cleanup audio processor
    free(proc.temp_buffer);
    free(proc.window_buffer);
    free(proc.effects.eq_bands);
    free(proc.effects.comp_threshold);
    free(proc.effects.reverb_buffer);
    swr_free(&proc.swr_ctx);

    return result;
}

int copy_buffer(const uint8_t *input, size_t input_size, uint8_t *output, size_t output_size) {
    size_t to_copy = input_size < output_size ? input_size : output_size;
    memcpy(output, input, to_copy);
    return (int)to_copy;
}
