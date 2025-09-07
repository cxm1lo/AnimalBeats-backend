const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Almacenamiento con Multer directamente en Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    let folder = "animalbeats";
    if (req.baseUrl.includes("Especies")) folder = "especies";
    if (req.baseUrl.includes("Razas")) folder = "razas";

    return {
      folder: folder,
      format: "png", // o usa file.originalname.split(".").pop() para mantener extensión
      public_id: Date.now().toString()
    };
  }
});

module.exports = { cloudinary, storage };
