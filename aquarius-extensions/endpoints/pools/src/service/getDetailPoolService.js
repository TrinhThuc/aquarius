const PAYMENT_STATUS_FAILED = '23'

export async function getDetailPool(req, res, services, exceptions, database) {
    const {
        ItemsService
    } = services;
    const {
        ServiceUnavailableException,
        InvalidQueryException
    } = exceptions;
    try {
        let id = req.params.id;
        let dateRequest = req.query.date;
        if (!dateRequest) {
            dateRequest = new Date();
        };
        const poolService = new ItemsService('pool', {
            accountability: req.accountability,
            schema: req.schema,
        });
        const orderService = new ItemsService('order', {
            accountability: req.accountability,
            schema: req.schema,
        });
        const poolResult = await poolService.readByQuery({
            "filter": {
                "id": {
                    "_eq": id
                }
            },
            "fields": ["*", "images.*", "pools.*", "services.service_id.*", "tickets.*", "pools.*", "pools.images.*"]
        });
        if (poolResult.length == 0) {
            throw new InvalidQueryException("Don't exist this pool")
        }
        const pool = poolResult[0];
        const orders = await orderService.readByQuery({
            "filter": {
                _and: [{
                        "pool_id": {
                            "_eq": id
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
        pool.tickets.forEach(ticketType => {
            let totalTicketQuantity = 0;
            orders.forEach(order => {
                let orderTotalQuantity = order.tickets.reduce((total, ticket) => {
                    if (ticket.ticket_id && ticket.ticket_id.ticket_type === ticketType.ticket_type) {
                        total += ticket.quantity;
                    }
                    return total;
                }, 0);
                totalTicketQuantity += orderTotalQuantity;
            });
            ticketType.ticket_remain = ticketType.total_ticket - totalTicketQuantity;
        });
        res.status(200).json({
            data: pool
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