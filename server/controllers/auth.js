import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Регистрация
export const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: "Username или email уже занят" });
    }

    const hash = await bcrypt.hash(password, 10);

    const newUser = new User({ username, email, password: hash });
    await newUser.save();

    const { password: _, ...userData } = newUser.toObject();

    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET || "secret123", { expiresIn: "30d" });

    res.json({ user: userData, token, message: "Регистрация прошла успешно" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Ошибка при создании пользователя" });
  }
};

// Логин
export const login = async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: "Пользователь не найден" });

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) return res.status(400).json({ message: "Неверный пароль" });

    const { password: _, ...userData } = user.toObject();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "secret123", { expiresIn: "30d" });

    res.json({ user: userData, token, message: "Вы вошли в систему" });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Ошибка при авторизации" });
  }
};

// Get Me
export const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: "Пользователь не найден" });

    const { password: _, ...userData } = user.toObject();

    res.json({ user: userData });
  } catch (err) {
    console.error("GetMe error:", err);
    res.status(500).json({ message: "Нет доступа" });
  }
};

// Получить всех пользователей
export const getAll = async (req, res) => {
  try {
    const users = await User.find().select("-password");
    res.json({ success: true, users });
  } catch (err) {
    console.error("GetAll error:", err);
    res.status(500).json({ success: false, message: "Ошибка при получении пользователей" });
  }
};
