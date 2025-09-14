import User from "../models/User.js";
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

// Register user
export const register = async (req, res) => {
    try {
      const { username, password } = req.body;
  
      // Проверяем, есть ли такой пользователь
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ message: "Пользователь уже существует" });
      }
  
      // Хэшируем пароль
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(password, salt);
  
      // Создаём пользователя
      const newUser = new User({
        username,
        password: hash,
      });
  
      await newUser.save();
  
      // Преобразуем в объект без пароля
      const { password: _, ...userData } = newUser.toObject();
  
      // Генерируем токен
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
      console.error(err);
      res.status(500).json({ message: "Ошибка при создании пользователя" });
    }
  };
  
  // Login user
  export const login = async (req, res) => {
    try {
      const { username, password } = req.body;
      const user = await User.findOne({ username });
  
      if (!user) {
        return res.status(400).json({ message: "Такого юзера не существует." });
      }
  
      const isPasswordCorrect = await bcrypt.compare(password, user.password);
      if (!isPasswordCorrect) {
        return res.status(400).json({ message: "Неверный пароль." });
      }
  
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "30d",
      });
  
      const { password: _, ...userData } = user._doc;
  
      res.json({
        user: userData,
        token,
        message: "Вы вошли в систему.",
      });
    } catch (error) {
      res.status(500).json({ message: "Ошибка при авторизации." });
    }
  };
  
  // Get me
  export const getMe = async (req, res) => {
    try {
      const user = await User.findById(req.userId);
      if (!user) {
        return res.status(404).json({ message: "Такого юзера не существует." });
      }
  
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "30d",
      });
  
      const { password: _, ...userData } = user._doc;
  
      res.json({ user: userData, token });
    } catch (error) {
      res.status(500).json({ message: "Нет доступа." });
    }
  };
  