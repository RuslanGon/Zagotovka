import User from "../models/User.js";
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

// Register user
export const register = async (req, res) => {
    try {
      const { username, email, password } = req.body;
  
      // Проверка уникальности username и email
      const existingUser = await User.findOne({ $or: [{ username }, { email }] });
      if (existingUser) {
        return res.status(400).json({ message: "Username или email уже занят" });
      }
  
      // Хэширование пароля
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(password, salt);
  
      // Создание пользователя
      const newUser = new User({
        username,
        email,
        password: hash,
      });
  
      await newUser.save();
  
      // Убираем пароль из ответа
      const { password: _, ...userData } = newUser.toObject();
  
      // Генерация токена
      const token = jwt.sign(
        { id: newUser._id },
        process.env.JWT_SECRET || "secret123",
        { expiresIn: "30d" }
      );
  
      res.json({
        user: userData,
        token,
        message: "Регистрация прошла успешно",
      });
    } catch (err) {
      console.error("Register error:", err);
      res.status(500).json({ message: "Ошибка при создании пользователя" });
    }
  };
  
  // Login user
  export const login = async (req, res) => {
    try {
      const { username, password } = req.body;
  
      if (!username || !password) {
        return res.status(400).json({ message: "Укажите username и пароль" });
      }
  
      // Ищем пользователя по username
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(400).json({ message: "Пользователь не найден" });
      }
  
      // Проверка пароля
      const isPasswordCorrect = await bcrypt.compare(password, user.password);
      if (!isPasswordCorrect) {
        return res.status(400).json({ message: "Неверный пароль" });
      }
  
      // Генерация токена
      const token = jwt.sign(
        { id: user._id },
        process.env.JWT_SECRET || "secret123",
        { expiresIn: "30d" }
      );
  
      const { password: _, ...userData } = user.toObject();
  
      res.json({
        user: userData,
        token,
        message: "Вы вошли в систему",
      });
    } catch (err) {
      console.error("Login error:", err);
      res.status(500).json({ message: "Ошибка при авторизации" });
    }
  };
  
  // Get me
  export const getMe = async (req, res) => {
    try {
      const user = await User.findById(req.userId);
      if (!user) {
        return res.status(404).json({ message: "Пользователь не найден" });
      }
  
      const token = jwt.sign(
        { id: user._id },
        process.env.JWT_SECRET || "secret123",
        { expiresIn: "30d" }
      );
  
      const { password: _, ...userData } = user.toObject();
  
      res.json({ user: userData, token });
    } catch (err) {
      console.error("GetMe error:", err);
      res.status(500).json({ message: "Нет доступа" });
    }
  };

//   getAll
export const getAll = async (req, res) => {
    try {
      const users = await User.find().select("-password"); // исключаем пароль из ответа
      res.json({
        success: true,
        users,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: "Ошибка при получении пользователей",
      });
    }
  };
  