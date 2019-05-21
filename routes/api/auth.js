const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const jwt = require('jsonwebtoken');
const config = require('config');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator/check');

// @route  GET api/auth
// @desc   Test route
// @access Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password'); // -password removes the password from returned data
        res.json(user);
    } catch(err) {
        console.error(err.message);
        res.status(500).send('Server error')
    }
});

// @route  POST api/auth
// @desc   Authenticate user & get token
// @access Public
router.post('/',
    [
        check('email', 'Please include a valid email').isEmail(),
        check(
            'password',
            'Password is required'
        ).exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) { // if there are errors
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password} = req.body;

        try {
            // See if user exists
            let user = await User.findOne({ email });

            if(!user) {
                return res
                    .status(400)
                    .json({ errors: [ { msg: 'Invalid credentials' } ] });
            }

            const isMatch = await bcrypt.compare(password, user.password); // first password is in plain-text, second password is hashed

            if(!isMatch) {
                return res
                    .status(400)
                    .json({ errors: [{ msg: 'Invalid Credentials' }] });
            }

            // Return jsonwebtoken
            const payload = {
                user: {
                    id: user.id
                }
            };

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                { expiresIn: 36000000 },
                (err, token) => {
                    if(err) throw err;
                    res.json({ token });
                });


        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server error');
        }


    }
);



module.exports = router;
