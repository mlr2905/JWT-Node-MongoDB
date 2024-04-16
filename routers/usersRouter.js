const { Router } = require('express');
const usersController = require('../controllers/usersController');

const router = Router();

router.post('', usersController.post)
router.get('/:id', usersController.get_by_id)
router.delete('/:id', usersController.delete)

module.exports = router;