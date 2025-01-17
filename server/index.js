import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import multer from 'multer';
import helmet from 'helmet';
import morgan from 'morgan';
import path from 'path';
import { fileURLToPath } from 'url';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import postRoutes from './routes/posts.js';
import { register } from './controllers/auth.js';
import { createPost } from './controllers/posts.js';
import { verifyToken } from './middlewares/auth.js';
import User from './models/User.js';
import Post from './models/Post.js';
import { users, posts } from './data/index.js';

/** Configuration */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();

app.use(express.json());
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: 'cross-origin' }));
app.use(morgan('dev'));
app.use(cors());
app.use('/assets', express.static(path.join(__dirname, 'public/assets')));

/** File storage */
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'publick/assets');
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage });

/* Routes with files */
app.post('/auth/register', upload.single('picture'), register);
app.post('/posts', verifyToken, upload.single('picture'), createPost);

/* Routes */
app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/posts', postRoutes);

/* mongoose setup */
const port = process.env.PORT || 3000;

mongoose
  .connect(process.env.MONGO_URL, {})
  .then(() => {
    app.listen(port, console.log('server running on the port: ', port));

    // User.insertMany(users);
    // Post.insertMany(posts);
  })
  .catch((err) => {
    console.log('database error: ', err);
  });
