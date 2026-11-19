package com.pigeon.voice.net;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Memory-safe native Android image downsampler and JPEG compressor for P2P image sharing.
 *
 * Uses two-pass BitmapFactory decoding with inSampleSize to avoid OutOfMemoryError on
 * high-resolution camera photos and limits payloads to fast encrypted chunks.
 */
public final class ImageCompressor {

    public static final int MAX_DIMENSION_PX = 1024;
    public static final int JPEG_QUALITY = 78;
    public static final int MAX_IMAGE_BYTES = 2 * 1024 * 1024; // 2 MB hard cap

    private ImageCompressor() {
    }

    public static byte[] compressUriToJpeg(Context context, Uri imageUri) throws IOException {
        if (context == null || imageUri == null) {
            throw new IOException("Invalid context or image URI");
        }

        // First pass: decode bounds only
        BitmapFactory.Options boundsOpts = new BitmapFactory.Options();
        boundsOpts.inJustDecodeBounds = true;
        try (InputStream is = context.getContentResolver().openInputStream(imageUri)) {
            if (is == null) {
                throw new IOException("Unable to open image stream");
            }
            BitmapFactory.decodeStream(is, null, boundsOpts);
        }

        if (boundsOpts.outWidth <= 0 || boundsOpts.outHeight <= 0) {
            throw new IOException("Selected file is not a valid image");
        }

        // Compute power-of-two inSampleSize
        BitmapFactory.Options decodeOpts = new BitmapFactory.Options();
        decodeOpts.inSampleSize = calculateInSampleSize(
                boundsOpts.outWidth,
                boundsOpts.outHeight,
                MAX_DIMENSION_PX,
                MAX_DIMENSION_PX);
        decodeOpts.inPreferredConfig = Bitmap.Config.RGB_565;

        Bitmap decoded;
        try (InputStream is = context.getContentResolver().openInputStream(imageUri)) {
            if (is == null) {
                throw new IOException("Unable to reopen image stream");
            }
            decoded = BitmapFactory.decodeStream(is, null, decodeOpts);
        }

        if (decoded == null) {
            throw new IOException("Failed to decode image bitmap");
        }

        // Scale down accurately if still larger than MAX_DIMENSION_PX
        Bitmap scaled = scaleDownIfNeeded(decoded, MAX_DIMENSION_PX);
        if (scaled != decoded) {
            decoded.recycle();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream(64 * 1024);
        scaled.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, baos);
        scaled.recycle();

        byte[] result = baos.toByteArray();
        if (result.length > MAX_IMAGE_BYTES) {
            throw new IOException("Compressed image exceeds 2 MB limit");
        }
        return result;
    }

    public static int calculateInSampleSize(int rawWidth, int rawHeight, int reqWidth, int reqHeight) {
        if (rawWidth <= 0 || rawHeight <= 0 || reqWidth <= 0 || reqHeight <= 0) {
            return 1;
        }
        int inSampleSize = 1;
        if (rawHeight > reqHeight || rawWidth > reqWidth) {
            final int halfHeight = rawHeight / 2;
            final int halfWidth = rawWidth / 2;
            while ((halfHeight / inSampleSize) >= reqHeight || (halfWidth / inSampleSize) >= reqWidth) {
                inSampleSize *= 2;
            }
        }
        return Math.max(1, inSampleSize);
    }

    private static Bitmap scaleDownIfNeeded(Bitmap src, int maxDimension) {
        int w = src.getWidth();
        int h = src.getHeight();
        if (w <= maxDimension && h <= maxDimension) {
            return src;
        }
        float ratio = Math.min((float) maxDimension / w, (float) maxDimension / h);
        int targetW = Math.max(1, Math.round(w * ratio));
        int targetH = Math.max(1, Math.round(h * ratio));
        return Bitmap.createScaledBitmap(src, targetW, targetH, true);
    }
}
