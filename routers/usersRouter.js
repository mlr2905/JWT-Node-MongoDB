const { Router } = require('express');
const usersController = require('../controllers/usersController');

const router = Router();

router.post('/signup', usersController.signup_post);
router.post('/login', usersController.login_post);
router.get('/logout', usersController.logout_get);
router.get('/data', usersController.get_protected_data);

// router.get('/search', usersController.search_users)
// router.get('/', usersController.encrypt_and_update_all_passwords)

// router.post('', usersController.post)
// router.get('/:id', usersController.get_by_id)
// router.delete('/:id', usersController.delete)
// router.delete('/', usersController.deleteAll)



module.exports = router;