import {
	getListPool
} from "./service/getListPoolService";
import {
	getDetailPool
} from "./service/getDetailPoolService";
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
	router.get('/', async (req, res) => {
		await getListPool(req, res, services, exceptions, database);
	});
	router.get('/:id', async (req, res) => {
		await getDetailPool(req, res, services, exceptions, database);
	});
};