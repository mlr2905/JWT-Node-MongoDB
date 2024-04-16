const { Router } = require('express');
const usersController = require('../controllers/usersController');

const router = Router();
router.get('/search', usersController.search_users)

router.post('', usersController.post)
router.get('/:id', usersController.get_by_id)
router.delete('/:id', usersController.delete)
// router.get('search', usersController.search_user)
router.get('/search', usersController.search_users)


module.exports = router;