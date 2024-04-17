const { Router } = require('express');
const usersController = require('../controllers/usersController');

const router = Router();

router.get('/search', usersController.search_users)
router.get('/', usersController.encrypt_and_update_all_passwords)

router.post('', usersController.post)
router.get('/:id', usersController.get_by_id)
router.delete('/:id', usersController.delete)
router.delete('/', usersController.deleteAll)

// router.get('search', usersController.search_user)


module.exports = router;