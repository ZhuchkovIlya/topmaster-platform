// server.js - Главный файл сервера
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs').promises;

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-super-secret-jwt-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Для статических файлов

// Временная база данных в памяти (замените на настоящую БД)
let users = [];
let orders = [];
let messages = [];
let executors = [];
let payments = [];

// Генератор ID
const generateId = () => Date.now() + Math.random().toString(36).substr(2, 9);

// Middleware для проверки JWT токена
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Токен доступа отсутствует' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Недействительный токен' });
        }
        req.user = user;
        next();
    });
};

// ================================
// АВТОРИЗАЦИЯ И РЕГИСТРАЦИЯ
// ================================

// Регистрация пользователя
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, phone, password, userType } = req.body;

        // Проверка на существующего пользователя
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
        }

        // Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, 10);

        // Создание пользователя
        const user = {
            id: generateId(),
            name,
            email,
            phone,
            password: hashedPassword,
            userType: userType || 'customer',
            isVerified: false,
            avatar: null,
            createdAt: new Date().toISOString()
        };

        users.push(user);

        // Создание JWT токена
        const token = jwt.sign({ 
            id: user.id, 
            email: user.email,
            userType: user.userType 
        }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({
            message: 'Пользователь успешно зарегистрирован',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                userType: user.userType,
                isVerified: user.isVerified
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера при регистрации' });
    }
});

// Вход пользователя
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Поиск пользователя
        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(400).json({ error: 'Неверный email или пароль' });
        }

        // Проверка пароля
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Неверный email или пароль' });
        }

        // Создание JWT токена
        const token = jwt.sign({ 
            id: user.id, 
            email: user.email,
            userType: user.userType 
        }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            message: 'Успешный вход',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                userType: user.userType,
                isVerified: user.isVerified
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера при входе' });
    }
});

// Получение профиля пользователя
app.get('/api/auth/profile', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'Пользователь не найден' });
    }

    res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        userType: user.userType,
        isVerified: user.isVerified,
        avatar: user.avatar
    });
});

// ================================
// УПРАВЛЕНИЕ ЗАКАЗАМИ
// ================================

// Получение всех заказов
app.get('/api/orders', (req, res) => {
    const { category, city, search } = req.query;
    
    let filteredOrders = orders.filter(order => order.status === 'open');
    
    if (category && category !== 'all') {
        filteredOrders = filteredOrders.filter(order => 
            order.category.toLowerCase().includes(category.toLowerCase())
        );
    }
    
    if (city) {
        filteredOrders = filteredOrders.filter(order => 
            order.city.toLowerCase().includes(city.toLowerCase())
        );
    }
    
    if (search) {
        filteredOrders = filteredOrders.filter(order => 
            order.title.toLowerCase().includes(search.toLowerCase()) ||
            order.description.toLowerCase().includes(search.toLowerCase())
        );
    }

    // Добавляем информацию о заказчике
    const ordersWithCustomer = filteredOrders.map(order => {
        const customer = users.find(u => u.id === order.customerId);
        return {
            ...order,
            customer: customer ? {
                id: customer.id,
                name: customer.name,
                avatar: customer.avatar,
                isVerified: customer.isVerified
            } : null
        };
    });

    res.json(ordersWithCustomer);
});

// Создание заказа
app.post('/api/orders', authenticateToken, (req, res) => {
    try {
        const { title, description, category, budget, city, deadline, address } = req.body;

        const order = {
            id: generateId(),
            customerId: req.user.id,
            title,
            description,
            category,
            budget: parseFloat(budget),
            city,
            address,
            deadline,
            status: 'open',
            responses: [],
            createdAt: new Date().toISOString()
        };

        orders.push(order);

        res.status(201).json({
            message: 'Заказ успешно создан',
            order
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка при создании заказа' });
    }
});

// Получение заказа по ID
app.get('/api/orders/:id', (req, res) => {
    const order = orders.find(o => o.id === req.params.id);
    if (!order) {
        return res.status(404).json({ error: 'Заказ не найден' });
    }

    const customer = users.find(u => u.id === order.customerId);
    res.json({
        ...order,
        customer: customer ? {
            id: customer.id,
            name: customer.name,
            avatar: customer.avatar,
            isVerified: customer.isVerified
        } : null
    });
});

// Откликнуться на заказ
app.post('/api/orders/:id/respond', authenticateToken, (req, res) => {
    try {
        const { message, price, timeline } = req.body;
        const orderId = req.params.id;

        const order = orders.find(o => o.id === orderId);
        if (!order) {
            return res.status(404).json({ error: 'Заказ не найден' });
        }

        if (order.customerId === req.user.id) {
            return res.status(400).json({ error: 'Нельзя откликаться на собственный заказ' });
        }

        // Проверяем, не откликался ли уже этот пользователь
        const existingResponse = order.responses.find(r => r.executorId === req.user.id);
        if (existingResponse) {
            return res.status(400).json({ error: 'Вы уже откликались на этот заказ' });
        }

        const executor = users.find(u => u.id === req.user.id);
        const response = {
            id: generateId(),
            executorId: req.user.id,
            executor: {
                id: executor.id,
                name: executor.name,
                avatar: executor.avatar,
                isVerified: executor.isVerified
            },
            message,
            price: parseFloat(price),
            timeline,
            createdAt: new Date().toISOString()
        };

        order.responses.push(response);

        res.json({
            message: 'Отклик успешно отправлен',
            response
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка при отправке отклика' });
    }
});

// ================================
// ИСПОЛНИТЕЛИ
// ================================

// Регистрация как исполнитель
app.post('/api/executors/register', authenticateToken, (req, res) => {
    try {
        const { 
            specialization, 
            experience, 
            description, 
            hourlyRate,
            workRadius,
            skills 
        } = req.body;

        // Проверяем, не зарегистрирован ли уже как исполнитель
        const existingExecutor = executors.find(e => e.userId === req.user.id);
        if (existingExecutor) {
            return res.status(400).json({ error: 'Вы уже зарегистрированы как исполнитель' });
        }

        const executor = {
            id: generateId(),
            userId: req.user.id,
            specialization,
            experience,
            description,
            hourlyRate: parseFloat(hourlyRate),
            workRadius,
            skills: skills || [],
            rating: 0,
            reviewsCount: 0,
            completedOrders: 0,
            isApproved: false, // Требует модерации
            createdAt: new Date().toISOString()
        };

        executors.push(executor);

        // Обновляем тип пользователя
        const user = users.find(u => u.id === req.user.id);
        if (user) {
            user.userType = 'executor';
        }

        res.status(201).json({
            message: 'Заявка на регистрацию исполнителя отправлена на модерацию',
            executor
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка при регистрации исполнителя' });
    }
});

// Получение списка исполнителей
app.get('/api/executors', (req, res) => {
    const { specialization, city, minRating } = req.query;
    
    let filteredExecutors = executors.filter(e => e.isApproved);
    
    if (specialization) {
        filteredExecutors = filteredExecutors.filter(e => 
            e.specialization.toLowerCase().includes(specialization.toLowerCase())
        );
    }
    
    if (minRating) {
        filteredExecutors = filteredExecutors.filter(e => e.rating >= parseFloat(minRating));
    }

    // Добавляем информацию о пользователе
    const executorsWithUser = filteredExecutors.map(executor => {
        const user = users.find(u => u.id === executor.userId);
        return {
            ...executor,
            user: user ? {
                id: user.id,
                name: user.name,
                avatar: user.avatar,
                isVerified: user.isVerified
            } : null
        };
    });

    res.json(executorsWithUser);
});

// ================================
// СИСТЕМА СООБЩЕНИЙ
// ================================

// Отправка сообщения
app.post('/api/messages', authenticateToken, (req, res) => {
    try {
        const { orderId, receiverId, content } = req.body;

        const message = {
            id: generateId(),
            orderId,
            senderId: req.user.id,
            receiverId,
            content,
            isRead: false,
            createdAt: new Date().toISOString()
        };

        messages.push(message);

        res.status(201).json({
            message: 'Сообщение отправлено',
            data: message
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка при отправке сообщения' });
    }
});

// Получение сообщений по заказу
app.get('/api/messages/:orderId', authenticateToken, (req, res) => {
    const orderId = req.params.orderId;
    const orderMessages = messages.filter(m => m.orderId === orderId);
    
    // Добавляем информацию об отправителях
    const messagesWithSenders = orderMessages.map(msg => {
        const sender = users.find(u => u.id === msg.senderId);
        return {
            ...msg,
            sender: sender ? {
                id: sender.id,
                name: sender.name,
                avatar: sender.avatar
            } : null
        };
    });

    res.json(messagesWithSenders);
});

// ================================
// ПЛАТЕЖИ (упрощенная версия)
// ================================

// Создание платежа
app.post('/api/payments/create', authenticateToken, (req, res) => {
    try {
        const { orderId, amount } = req.body;

        const order = orders.find(o => o.id === orderId);
        if (!order) {
            return res.status(404).json({ error: 'Заказ не найден' });
        }

        if (order.customerId !== req.user.id) {
            return res.status(403).json({ error: 'Нет прав для оплаты этого заказа' });
        }

        const payment = {
            id: generateId(),
            orderId,
            customerId: req.user.id,
            amount: parseFloat(amount),
            status: 'pending',
            paymentUrl: `https://topmaster.ru/payment/${generateId()}`, // Заглушка
            createdAt: new Date().toISOString()
        };

        payments.push(payment);

        res.json({
            message: 'Платеж создан',
            payment,
            redirectUrl: payment.paymentUrl
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка при создании платежа' });
    }
});

// Подтверждение платежа
app.post('/api/payments/:id/confirm', authenticateToken, (req, res) => {
    const payment = payments.find(p => p.id === req.params.id);
    if (!payment) {
        return res.status(404).json({ error: 'Платеж не найден' });
    }

    payment.status = 'confirmed';
    payment.confirmedAt = new Date().toISOString();

    // Обновляем статус заказа
    const order = orders.find(o => o.id === payment.orderId);
    if (order) {
        order.status = 'paid';
    }

    res.json({
        message: 'Платеж подтвержден',
        payment
    });
});

// ================================
// ПОИСК И ФИЛЬТРАЦИЯ
// ================================

// Поиск по всем сущностям
app.get('/api/search', (req, res) => {
    const { query, type } = req.query;
    
    if (!query) {
        return res.status(400).json({ error: 'Поисковый запрос не указан' });
    }

    const results = {};

    if (!type || type === 'orders') {
        results.orders = orders.filter(order => 
            order.title.toLowerCase().includes(query.toLowerCase()) ||
            order.description.toLowerCase().includes(query.toLowerCase()) ||
            order.category.toLowerCase().includes(query.toLowerCase())
        );
    }

    if (!type || type === 'executors') {
        const matchingExecutors = executors.filter(executor => 
            executor.specialization.toLowerCase().includes(query.toLowerCase()) ||
            executor.description.toLowerCase().includes(query.toLowerCase())
        );
        
        results.executors = matchingExecutors.map(executor => {
            const user = users.find(u => u.id === executor.userId);
            return {
                ...executor,
                user: user ? {
                    id: user.id,
                    name: user.name,
                    avatar: user.avatar
                } : null
            };
        });
    }

    res.json(results);
});

// ================================
// СТАТИСТИКА И АНАЛИТИКА
// ================================

// Получение статистики платформы
app.get('/api/stats', (req, res) => {
    const stats = {
        totalUsers: users.length,
        totalExecutors: executors.length,
        totalOrders: orders.length,
        completedOrders: orders.filter(o => o.status === 'completed').length,
        totalPayments: payments.length,
        totalRevenue: payments
            .filter(p => p.status === 'confirmed')
            .reduce((sum, p) => sum + p.amount, 0)
    };

    res.json(stats);
});

// ================================
// СЛУЖЕБНЫЕ МАРШРУТЫ
// ================================

// Проверка здоровья сервера
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Главная страница - отдаем HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 404 для API
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'API endpoint не найден' });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`🚀 TopMaster сервер запущен на порту ${PORT}`);
    console.log(`📡 API доступно по адресу: http://localhost:${PORT}/api`);
    console.log(`🌐 Веб-сайт доступен по адресу: http://localhost:${PORT}`);
});

// Обработка ошибок
process.on('uncaughtException', (error) => {
    console.error('Необработанная ошибка:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Необработанное отклонение промиса:', reason);
    process.exit(1);
});

module.exports = app;
