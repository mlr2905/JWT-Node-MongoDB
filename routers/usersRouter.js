const { Router } = require('express');
const usersController = require('../controllers/usersController');
const path = require('path');


const router = Router();
// router.get('/', (req, res) => {
//     res.sendFile(path.join(__dirname, '../static/500.html'));
// });
router.post('/log', usersController.loginWithCredential);
router.post('/reg', usersController.registerCredential);

router.post('/signup', usersController.signup_post);
router.post('/login', usersController.login_post);
router.get('/logout', usersController.logout_get);
router.get('/data', usersController.validate_token );

router.get('/decrypt/search', usersController.decryptPassword)
router.get('/search', usersController.search_users)
router.post('/authcode', usersController.authcode)
router.post('/verifyCode', usersController.verifyCode)

// router.use((req, res) => {
//     res.status(404).sendFile(path.join(__dirname, '../static/404.html'));
// });
// router.get('/', usersController.encrypt_and_update_all_passwords)

// router.post('', usersController.post)
// router.get('/:id', usersController.get_by_id)
// router.delete('/:id', usersController.delete)
// router.delete('/', usersController.deleteAll)



module.exports = router;