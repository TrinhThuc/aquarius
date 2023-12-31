export default ({
	filter,
	action
}, {
	services,
	getSchema,
	exceptions,
	logger,
	env
}) => {

	const {
		ItemsService
	} = services;
	const {
		InvalidPayloadException
	} = exceptions
	filter('order.items.create', async (payload, event, collection) => {
		console.log('Creating Item!');
		const ticketService = new ItemsService('ticket', {
			schema: await getSchema()
		});
		const ticketRequests = payload.tickets.create;
		if (!ticketRequests || ticketRequests.length == 0) {
			console.log("Invalid ticket request");
			throw new InvalidPayloadException("Invalid ticket request")
		}
		if (!validateEmail(payload.email_receiver)) {
			console.log("Invalid email receiver");
			throw new InvalidPayloadException("Invalid email receiver")
		}
		var checkTotalAmount = 0;
		let checkDateAvailable = null;
		const promises = ticketRequests.map(async ticketRequest => {
			let ticketAmount = 0
			if (!ticketRequest.ticket_id || !ticketRequest.quantity) {
				console.log("Invalid ticket request");
				throw new InvalidPayloadException("Invalid ticket request")
			}
			if (ticketRequest.date_available) {
				if (!checkDateAvailable) {
					checkDateAvailable = ticketRequest.date_available;
				} else {
					if (checkDateAvailable != ticketRequest.date_available) {
						console.log("Invalid date available request");
						throw new InvalidPayloadException("Invalid date available request")
					}
				}
			} else {
				ticketRequest.date_available = getCurrentDate();
			}
			let ticket = await ticketService.readOne(ticketRequest.ticket_id, {
				fields: ["*"]
			});
			ticketAmount = ticket.price * ticketRequest.quantity
			if (ticketRequest.total_amount) {
				if (ticketAmount != ticketRequest.total_amount) {
					console.log("Ticket total amount not match");
					throw new InvalidPayloadException("Ticket total amount not match")
				}
			} else {
				ticketRequest.total_amount = ticketAmount
			}
			checkTotalAmount += ticketAmount;
		});

		await Promise.all(promises);

		if (payload.total_amount) {
			if (checkTotalAmount != payload.total_amount) {
				console.log("Total amount not match : ");
				console.log("Request : " + payload.total_amount);
				console.log(("CheckTotalAmount : " + checkTotalAmount));
				throw new InvalidPayloadException("Total amount not match")
			}
		} else {
			payload.total_amount = checkTotalAmount
		}
		console.log("Pass validate order");
	});

	// action('order.items.create', async (payload, event, collection) => {

	// });
};

function validateEmail(email) {
	const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	return regex.test(email);
}

function getCurrentDate() {
	const currentDate = new Date();
	const year = currentDate.getFullYear();
	const month = (currentDate.getMonth() + 1).toString().padStart(2, '0'); // Tháng bắt đầu từ 0
	const day = currentDate.getDate().toString().padStart(2, '0');

	const formattedDate = `${year}-${month}-${day}`;
	return formattedDate;
}