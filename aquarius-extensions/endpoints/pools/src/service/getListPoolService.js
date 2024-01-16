const PAYMENT_STATUS_FAILED = '23'

export async function getListPool(req, res, services, exceptions, database) {
    const {
        ItemsService
    } = services;
    const {
        ServiceUnavailableException,
        InvalidQueryException
    } = exceptions;
    console.log(database);
    try {
        let page = req.query.page;
        let limit = req.query.limit;
        let sort = req.query.sort;
        let serviceRequest = req.query.service;
        let fromPrice = req.query.from_price;
        let toPrice = req.query.to_price;
        let openingTime = req.query.opening_time;
        let closingTime = req.query.closing_time;
        if (!page || !limit) {
            page = 1;
            limit = 4;
        }
        console.log(sort);
        let locationRequest = req.query['location'];
        console.log(locationRequest);
        let dateRequest = req.query.date;
        if (!dateRequest) {
            dateRequest = new Date();
        };
        const ticketService = new ItemsService('ticket', {
            accountability: req.accountability,
            schema: req.schema,
        });
        const seService = new ItemsService('service_pool', {
            accountability: req.accountability,
            schema: req.schema,
        });
        const orderService = new ItemsService('order', {
            accountability: req.accountability,
            schema: req.schema,
        });
        const poolFilesService = new ItemsService('pool_files', {
            accountability: req.accountability,
            schema: req.schema,
        });
        let query = `SELECT distinct(p.*)
			FROM (SELECT p.*,
						 t.id                                   AS ticket_id,
						 t.price                                AS price,
						 ROW_NUMBER() OVER (PARTITION BY p.id ) AS row_num
				  FROM pool p
						   LEFT JOIN ticket t ON t.pool_id = p.id) AS p
						   LEFT JOIN service_pool s on p.id = s.pool_id
			WHERE row_num = 1
			`;
        if (locationRequest) {
            locationRequest = locationRequest
                .toLowerCase()
                .normalize('NFD')
                .replace(/[\u0300-\u0302\u0306\u0309\u0323]/g, '')
                .replace(/đ/g, 'd')
                .replace(/[^a-zA-Z0-9\s~`!@#$%^&*()_\-+={}\[\];:'"<>,.?/|]/g, '')
                .replace(/\s+/g, ''); // Remove additional spaces
            query = query + ' AND LOCATION_SEARCHING LIKE ' + "'%" + locationRequest + "%' ";
        };
        console.log(locationRequest);
        if (openingTime && closingTime) {
            query = query + " AND p.OPENING_TIME >= " + openingTime + " AND p.CLOSING_TIME <= " + closingTime;
        }
        if (fromPrice && toPrice) {
            query = query + " AND p.PRICE >= " + fromPrice + " AND p.PRICE <= " + toPrice;
        }
        if (sort) {
            if (sort.includes("-")) {
                sort = sort.replace(/^-/, "") + " DESC";
                query = query + ' ORDER BY p.' + sort;
            }
        }
        const countQuery = 'SELECT COUNT(*) AS total FROM ( ' + query + ' ) p';
        query = query + ' LIMIT ' + limit;
        query = query + ' OFFSET ' + limit * (page - 1)
        console.log(query);
        console.log(countQuery);
        const result = await database.raw(query);
        const totalResult = await database.raw(countQuery);
        let pools = result.rows;
        let total = totalResult.rows[0] ? totalResult.rows[0].total : 0;
        const poolPromises = pools.map(async pool => {
            const tickets = await ticketService.readByQuery({
                "filter": {
                    "pool_id": {
                        "_eq": pool.id
                    }
                },
                fields: ['*']
            });

            const services = await seService.readByQuery({
                "filter": {
                    "pool_id": {
                        "_eq": pool.id
                    }
                },
                fields: ["*", "service_id.*"]
            });
            const orders = await orderService.readByQuery({
                "filter": {
                    _and: [{
                            "pool_id": {
                                "_eq": pool.id
                            }
                        },
                        {
                            "order_status": {
                                "_neq": PAYMENT_STATUS_FAILED
                            }
                        }
                    ]

                },
                "deep": {
                    "tickets": {
                        "_filter": {
                            "date_available": {
                                "_eq": dateRequest
                            }
                        }
                    }
                },
                fields: ["*", "tickets.*", "tickets.ticket_id.ticket_type"]
            });
            let ticketSold = 0;
            orders.forEach(order => {
                order.tickets.forEach(ticket => {
                    if (ticket.ticket_id.ticket_type === 'ADULT') {
                        ticketSold += ticket.quantity;
                    }
                });
            });
            console.log(ticketSold);
            const adultTicket = tickets.find(ticket => ticket.ticket_type === "ADULT");
            const totalAdultTickets = adultTicket ? adultTicket.total_ticket : 0;
            const images = await poolFilesService.readByQuery({
                "filter": {
                    "pool_id": {
                        "_eq": pool.id
                    }
                },
                fields: ["directus_files_id"]
            });
            pool.ticket_available = totalAdultTickets - ticketSold;
            pool.images = images;
            pool.tickets = tickets;
            pool.services = services;
            pool.orders = orders;
            return pool; // Return the modified pool object
        });
        // Use Promise.all to wait for all promises to resolve
        let updatedPools = await Promise.all(poolPromises);
        let filteredPools = updatedPools;
        if (serviceRequest) {
            filteredPools = updatedPools.filter(pool => {
                const serviceArr = serviceRequest.split(",");
                var check = serviceArr.every(function (serviceReq) {
                    return pool.services.some(function (service) {
                        return checkService(service, serviceReq);
                    });
                });
                return check && pool.ticket_available > 0;
            });
        }
        res.json({
            "data": filteredPools,
            "total": total
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
};

function checkService(service, request) {
    return service.service_id.id == request;
}