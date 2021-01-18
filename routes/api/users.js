const express = require("express");
const { check, validationResult } = require("express-validator/check");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const config = require("config");
const User = require("../../models/User");

// @route       POST api/users
// @desc        Register user
// @access      Public
router.post(
	"/",
	[
		check("name", "Name is required").notEmpty(),
		check("email", "Please include a valid email").isEmail(),
		check(
			"password",
			"Please enter a password with 6 or more characters"
		).isLength({ min: 6 }),
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}

		const { name, email, password } = req.body;

		try {
			// See if the user exists
			let user = await User.findOne({ email });
			if (user) {
				return res.status(400).json({
					errors: [
						{
							message: "User already exits",
						},
					],
				});
			}

			// Get users gravatar
			const avatar = gravatar.url(email, {
				s: "200",
				r: "pg",
				d: "mm",
			});

			user = new User({
				name,
				email,
				avatar,
				password,
			});

			// Encrypt password
			const salt = await bcrypt.genSalt(10);
			user.password = await bcrypt.hash(password, salt);

			// Return jsonWebToken
			const payload = {
				user: {
					id: user.id,
				},
			};

			jwt.sign(
				payload,
				config.get("jwtSecret"),
				{ expiresIn: 360000 },
				(error, token) => {
					if (error) throw error;
					res.json({ token });
				}
			);

			await user.save();
		} catch (error) {
			console.error(error.message);
			res.status(500).send("Server error");
		}
	}
);

module.exports = router;
