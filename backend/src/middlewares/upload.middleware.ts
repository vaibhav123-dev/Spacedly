import multer from 'multer';
import path from 'path';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import cloudinary from '../config/cloudinary';
import { optimizeImage, isImage, getOptimalFormat } from '../utils/imageOptimizer';

// Configure Cloudinary storage with Sharp optimization
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    // Generate unique public_id
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const nameWithoutExt = path.parse(file.originalname).name;
    
    return {
      folder: 'spacedly/attachments', // Organize files in folders
      public_id: `${nameWithoutExt}-${uniqueSuffix}`,
      resource_type: 'auto', // Auto-detect resource type
      // For images, we'll optimize with Sharp before upload
      // For other files, upload as-is
    };
  },
});

// File filter - allow specific file types
const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  // Allowed file types
  const allowedTypes = /jpeg|jpg|png|gif|webp|pdf|doc|docx|txt|xls|xlsx|ppt|pptx/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only images, PDFs, and documents are allowed.'));
  }
};

// Configure multer with memory storage (for Sharp processing)
export const upload = multer({
  storage: multer.memoryStorage(), // Store in memory first for Sharp processing
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max file size
  },
  fileFilter: fileFilter,
});

// Helper function to upload single file to Cloudinary
const uploadToCloudinary = (buffer: Buffer, originalname: string, mimetype: string): Promise<any> => {
  return new Promise((resolve, reject) => {
    // Determine resource type based on mimetype
    let resourceType: 'image' | 'raw' | 'video' | 'auto' = 'auto';
    
    if (mimetype.startsWith('image/')) {
      resourceType = 'image';
    } else if (mimetype.startsWith('video/')) {
      resourceType = 'video';
    } else {
      // For PDFs, documents, etc., use 'raw'
      resourceType = 'raw';
    }

    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'spacedly/attachments',
        public_id: `${path.parse(originalname).name}-${Date.now()}-${Math.round(Math.random() * 1e9)}`,
        resource_type: resourceType,
      },
      (error, result) => {
        if (error) {
          console.error('Cloudinary upload error:', error);
          return reject(error);
        }
        resolve(result);
      }
    );

    const { Readable } = require('stream');
    const bufferStream = Readable.from(buffer);
    bufferStream.pipe(uploadStream);
  });
};

// Middleware to optimize and upload multiple files to Cloudinary
export const optimizeAndUpload = async (req: any, res: any, next: any) => {
  try {
    const files = req.files as Express.Multer.File[];
    
    if (!files || files.length === 0) {
      return next();
    }

    const uploadedFiles: any[] = [];
    let totalOriginalSize = 0;
    let totalOptimizedSize = 0;

    // Process each file
    for (const file of files) {
      const originalSize = file.size;
      totalOriginalSize += originalSize;

      // Check if file is an image
      if (isImage(file.mimetype)) {
        console.log(`Optimizing image: ${file.originalname} (${(originalSize / 1024 / 1024).toFixed(2)}MB)`);

        // Optimize image with Sharp
        const format = getOptimalFormat(file.mimetype);
        const optimizedBuffer = await optimizeImage(file.buffer, {
          quality: 70, // Aggressive compression
          maxWidth: 1920,
          maxHeight: 1080,
          format,
        });

        const optimizedSize = optimizedBuffer.length;
        totalOptimizedSize += optimizedSize;
        const compressionRatio = Math.round(((originalSize - optimizedSize) / originalSize) * 100);
        
        console.log(`Image optimized: ${(optimizedSize / 1024 / 1024).toFixed(2)}MB (${compressionRatio}% reduction)`);

        // Upload optimized image to Cloudinary
        const result = await uploadToCloudinary(optimizedBuffer, file.originalname, file.mimetype);
        
        // Update file object with Cloudinary info
        uploadedFiles.push({
          ...file,
          path: result.secure_url,
          filename: result.public_id,
          cloudinaryResult: result,
          optimizationStats: {
            originalSize,
            optimizedSize,
            compressionRatio,
          },
        });
      } else {
        // For non-image files, upload directly to Cloudinary
        console.log(`Uploading non-image file: ${file.originalname}`);
        totalOptimizedSize += originalSize;

        const result = await uploadToCloudinary(file.buffer, file.originalname, file.mimetype);
        
        uploadedFiles.push({
          ...file,
          path: result.secure_url,
          filename: result.public_id,
          cloudinaryResult: result,
        });
      }
    }

    // Calculate overall compression
    const overallCompression = Math.round(((totalOriginalSize - totalOptimizedSize) / totalOriginalSize) * 100);
    console.log(`\nTotal: ${files.length} files uploaded`);
    console.log(`Original size: ${(totalOriginalSize / 1024 / 1024).toFixed(2)}MB`);
    console.log(`Optimized size: ${(totalOptimizedSize / 1024 / 1024).toFixed(2)}MB`);
    console.log(`Overall compression: ${overallCompression}%\n`);

    // Replace req.files with uploaded files info
    req.files = uploadedFiles;
    req.optimizationStats = {
      totalFiles: files.length,
      totalOriginalSize,
      totalOptimizedSize,
      overallCompression,
    };

    next();
  } catch (error) {
    console.error('Upload middleware error:', error);
    next(error);
  }
};
