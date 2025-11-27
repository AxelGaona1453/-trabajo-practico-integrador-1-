import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { comparePassword, generateToken } from '../helpers/jwt.helper.js';
import { generateToken } from '../helpers/jwt.helper.js';
import { hashPassword } from '../helpers/bcrypt.helper.js';

export const register = async (req, res) => {
	const { username, email, password, role } = req.body;
	try {
		const hashedPassword = await bcrypt.hash(password, 10);
		const user = await UserModel.create({
			username: username,
			email: email,
			password: hashedPassword,
			role: role,
		});

		res.status(201).json({
			msg: 'Usuario registrado correctamente',
		});
	} catch (error) {
		res.status(500).json({
			msg: 'Error interno del servidor',
		});
	}
};

export const login = async (req, res) => {
	const { username, password } = req.body;
	try {
		const user = await UserModel.findOne({
			where: { username: username },
		});
		if (!user) {
			return res.status(401).json({ message: 'Credenciales inválidas.' });
		}
		const validPassword = await comparePassword(password, user.password);
		if (!validPassword) {
			return res.status(401).json({ message: 'Credenciales inválidas' });
		}

		const token = generateToken(user);

		res.cookie('token', token, {
			httpOnly: true,
			maxAge: 1000 * 60 * 60,
		});

		return res.status(200).json({
			msg: 'Sesión iniciada correctamente',
		});
	} catch (error) {
		res.status(500).json({
			msg: 'Error interno del servidor.',
		});
	}
};

export const logout = (req, res) => {
	res.clearCookie('token');
	return res.json({ message: 'Logout exitoso' });
};
