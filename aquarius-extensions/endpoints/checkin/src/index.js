const ORDER_STATUS_SUCCESS = "00"
const ORDER_STATUS_CHECKIN_SUCCESS = "55"

export default (router, {
	services,
	exceptions,
	database
}) => {
	const {
		ItemsService
	} = services;
	const {
		ServiceUnavailableException,
		InvalidQueryException
	} = exceptions;
	router.get('/order/:id', async (req, res) => {
		try {
			let id = req.params.id;
			const orderService = new ItemsService('order', {
				accountability: req.accountability,
				schema: req.schema,
			});
			const order = await orderService.readByQuery({
				"filter": {
					_and: [{
							"id": {
								"_eq": id
							}
						},
						{
							"order_status": {
								"_eq": ORDER_STATUS_SUCCESS
							}
						}
					]

				},
				"fields": ["*"]
			});
			if (!order || order.length == 0) {
				console.log("Invalid request");
				throw new InvalidQueryException("Invalid request")
			}
			const response = await orderService.updateOne(id, {
				order_status: ORDER_STATUS_CHECKIN_SUCCESS
			})
			res.status(200).json({
				data: response,
				message: "Checkin Success !"
			});
		} catch (error) {
			if (!error.status) {
				error.status = 503
			}
			res.status(error.status).json({
				error: error,
				message: error.message
			});
			return;
		}
	});
};