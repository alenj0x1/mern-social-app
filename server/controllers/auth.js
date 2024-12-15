import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

/**
 * Register user
 * @param {Request} req
 * @param {Response} res
 */
export const register = async (req, res) => {
  try {
    const { firstName, lastName, email, password, picturePath, frinds, location, occupation } = req.body;

    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = new User({
      firstName,
      lastName,
      email,
      password: passwordHash,
      picturePath,
      frinds,
      location,
      occupation,
    });

    const savedUser = await newUser.save();
    res.status(201).json(savedUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/**
 * Login
 * @param {Request} req
 * @param {Response} res
 */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ msg: 'user does not exists.' });

    const isMatchPassword = await bcrypt.compare(password, user.password);
    if (!isMatchPassword) return res.status(400).json({ msg: 'incorrect credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    delete user.password;

    res.status(200).json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
