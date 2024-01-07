import jwt from 'jsonwebtoken';

export default (router, {
	services,
	exceptions,
	database,
	env
}) => {
	const {
		UsersService
	} = services
	const {
		InvalidPayloadException,
		ForbiddenException,
		ServiceUnavailableException
	} = exceptions

	router.post('/activate', async (req, res, next) => {
		try {
			const {
				token
			} = req.body

			const {
				email,
				scope
			} = jwt.verify(token, env.SECRET, {
				issuer: 'directus'
			})

			if (scope !== 'invite')
				return next(
					new ForbiddenException(
						`You are not allowed to perform this operation.`
					)
				)

			// Find user in DB by email
			const user = await database
				.select('id', 'status')
				.from('directus_users')
				.where({
					email
				})
				.first()

			// Check user status - must be "invited"
			if (user?.status !== 'invited') {
				return next(
					new InvalidPayloadException(
						`Email address ${email} hasn't been invited.`
					)
				)
			}

			const usersService = new UsersService({
				schema: req.schema
			})
			await usersService.updateOne(user.id, {
				status: 'active'
			})
			res.status(200).json({
				data: user,
				message: "Active Success !"
			});
		} catch (error) {
			return next(new ServiceUnavailableException(error.message))
		}
	})
}