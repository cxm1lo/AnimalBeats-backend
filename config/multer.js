import multer from "multer";

// Usamos memoria, no guardamos en disco
const storage = multer.memoryStorage();
const upload = multer({ storage });

export default upload;

