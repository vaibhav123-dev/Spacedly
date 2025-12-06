import sharp from 'sharp';
import path from 'path';

interface OptimizationOptions {
  quality?: number;
  maxWidth?: number;
  maxHeight?: number;
  format?: 'webp' | 'jpeg' | 'png';
}

/**
 * Ultra-optimize images with Sharp
 * - Converts to WebP for maximum compression
 * - Strips metadata
 * - Resizes to max dimensions
 * - Progressive rendering
 * - Quality optimization
 */
export const optimizeImage = async (
  inputBuffer: Buffer,
  options: OptimizationOptions = {}
): Promise<Buffer> => {
  const {
    quality = 70, // Aggressive compression (70% quality)
    maxWidth = 1920, // Full HD width
    maxHeight = 1080, // Full HD height
    format = 'webp', // Default to WebP for best compression
  } = options;

  try {
    // Start Sharp processing
    let pipeline = sharp(inputBuffer);

    // Get image metadata
    const metadata = await pipeline.metadata();

    // Resize if image is larger than max dimensions
    if (
      metadata.width &&
      metadata.height &&
      (metadata.width > maxWidth || metadata.height > maxHeight)
    ) {
      pipeline = pipeline.resize(maxWidth, maxHeight, {
        fit: 'inside', // Maintain aspect ratio
        withoutEnlargement: true, // Don't upscale small images
      });
    }

    // Convert to optimal format
    if (format === 'webp') {
      pipeline = pipeline.webp({
        quality,
        effort: 6, // Higher effort = better compression (0-6)
        lossless: false,
      });
    } else if (format === 'jpeg') {
      pipeline = pipeline.jpeg({
        quality,
        progressive: true, // Progressive rendering
        optimizeScans: true,
        mozjpeg: true, // Use mozjpeg for better compression
      });
    } else if (format === 'png') {
      pipeline = pipeline.png({
        quality,
        compressionLevel: 9, // Maximum compression
        progressive: true,
      });
    }

    // Strip metadata (EXIF, etc.) to reduce file size
    pipeline = pipeline.withMetadata({
      // Keep only essential metadata
      orientation: metadata.orientation,
    });

    // Convert to buffer
    return await pipeline.toBuffer();
  } catch (error) {
    console.error('Image optimization error:', error);
    // Return original buffer if optimization fails
    return inputBuffer;
  }
};

/**
 * Generate thumbnail from image
 */
export const generateThumbnail = async (
  inputBuffer: Buffer,
  size: number = 300
): Promise<Buffer> => {
  try {
    return await sharp(inputBuffer)
      .resize(size, size, {
        fit: 'cover',
        position: 'center',
      })
      .webp({
        quality: 70,
        effort: 6,
      })
      .toBuffer();
  } catch (error) {
    console.error('Thumbnail generation error:', error);
    return inputBuffer;
  }
};

/**
 * Determine if file is an image
 */
export const isImage = (mimetype: string): boolean => {
  return mimetype.startsWith('image/');
};

/**
 * Get optimal format based on original format
 */
export const getOptimalFormat = (
  mimetype: string
): 'webp' | 'jpeg' | 'png' => {
  // Always use WebP for maximum compression
  // WebP supports both lossy and lossless compression
  if (mimetype.includes('png')) {
    return 'webp'; // PNG -> WebP (huge savings!)
  }
  if (mimetype.includes('jpeg') || mimetype.includes('jpg')) {
    return 'webp'; // JPEG -> WebP (better compression)
  }
  if (mimetype.includes('gif')) {
    return 'webp'; // GIF -> WebP
  }
  return 'webp'; // Default to WebP
};

/**
 * Calculate compression ratio
 */
export const calculateCompressionRatio = (
  originalSize: number,
  optimizedSize: number
): number => {
  return Math.round(((originalSize - optimizedSize) / originalSize) * 100);
};
