import {
	createPaymentUrlService
} from "./service/createPaymentUrlService";
import {
	vnpayReturn
} from "./service/vnpayReturnService";
export default (router, {
	services,
	exceptions,
	database,
	env
}) => {
	const {
		ItemsService
	} = services;
	const {
		ServiceUnavailableException,
		InvalidQueryException
	} = exceptions;
	router.get('/create_payment_url', async (req, res) => {
		await createPaymentUrlService(req, res, services, exceptions, database, env);
	});
	router.get('/vnpay_return', async (req, res) => {
		await vnpayReturn(req, res, services, exceptions, database, env);
	});
};