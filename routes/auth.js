'use strict';

/** Routes for authentication. */

const jsonschema = require('jsonschema');

const User = require('../models/user');
const express = require('express');
const router = new express.Router();
const { createToken } = require('../helpers/tokens');
const userAuthSchema = require('../schemas/userAuth.json');
const userRegisterSchema = require('../schemas/userRegister.json');
const { BadRequestError } = require('../expressError');

/** POST /auth/token:  { username, password } => { token }
 *
 * Returns JWT token which can be used to authenticate further requests.
 *
 * Authorization required: none
 */

router.post('/token', async function (req, res, next) {
	try {
		// compares the request body to the schema to verify inputs (username, password) from Login Form on frontend
		const validator = jsonschema.validate(req.body, userAuthSchema);
		if (!validator.valid) {
			const errs = validator.errors.map((e) => e.stack);
			throw new BadRequestError(errs);
		}

		// takes (username, password) and runs authentication to create token.
		// runs authentication function from User model
		// returns token
		const { username, password } = req.body;
		const user = await User.authenticate(username, password);
		const token = createToken(user);
		return res.json({ token });
	} catch (err) {
		return next(err);
	}
});

/** POST /auth/register:   { user } => { token }
 *
 * user must include { username, password, firstName, lastName, email }
 *
 * Returns JWT token which can be used to authenticate further requests.
 *
 * Authorization required: none
 */

router.post('/register', async function (req, res, next) {
	try {
		// validates signup form inputs from frontend and verifies if they match schema
		const validator = jsonschema.validate(req.body, userRegisterSchema);
		if (!validator.valid) {
			const errs = validator.errors.map((e) => e.stack);
			throw new BadRequestError(errs);
		}

		// registers new user with isAdmin set to false as default
		// returns token and status 201 meaning created
		const newUser = await User.register({ ...req.body, isAdmin: false });
		const token = createToken(newUser);
		return res.status(201).json({ token });
	} catch (err) {
		return next(err);
	}
});

module.exports = router;
