// const request = require('request');
import moment from 'moment';
import PAYMENT_STATUS from '../common/paymentStatus';

const PENDING_PAYMENT_STATUS = '05';

export async function createPaymentUrlService(req, res, services, exceptions, database, env) {
    const {
        ItemsService
    } = services;
    const {
        ServiceUnavailableException,
        InvalidQueryException
    } = exceptions;
    try {
        process.env.TZ = 'Asia/Ho_Chi_Minh';

        let date = new Date();
        let createDate = moment(date).format('YYYYMMDDHHmmss');

        let ipAddr = req.headers['x-forwarded-for'] ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            req.connection.socket.remoteAddress;

        let tmnCode = env['vnp_TmnCode'];
        let secretKey = env['vnp_HashSecret'];
        let vnpUrl = env['vnp_Url'];
        let returnUrl = env['vnp_ReturnUrl'];
        let orderId = req.query.order_id;
        let amount = req.query.amount;
        let bankCode = req.query.bank_code;
        if (!orderId || !amount) {
            console.log("Missing request");
            throw new InvalidQueryException("Missing request");
        }
        const orderService = new ItemsService('order', {
            accountability: req.accountability,
            schema: req.schema
        });
        const order = await orderService.readOne(orderId, {
            fields: ["*"]
        });
        if (!order) {
            console.log("Order not exist");
            throw new InvalidQueryException("Order not exist");
        }
        if (order.total_amount != amount) {
            console.log("Total amount not match");
            throw new InvalidQueryException("Total amount not match");
        }
        let locale = req.query.language;
        if (!locale || locale === null || locale === '') {
            locale = 'vn';
        }
        let currCode = 'VND';
        let vnp_Params = {};

        vnp_Params['vnp_Version'] = '2.1.0';
        vnp_Params['vnp_Command'] = 'pay';
        vnp_Params['vnp_TmnCode'] = tmnCode;
        vnp_Params['vnp_Locale'] = locale;
        vnp_Params['vnp_CurrCode'] = currCode;
        vnp_Params['vnp_TxnRef'] = moment(date).format('YYYYMMDDHHmmss');
        vnp_Params['vnp_OrderInfo'] = 'Thanh toan cho ma GD:' + orderId;
        vnp_Params['vnp_OrderType'] = 'other';
        vnp_Params['vnp_Amount'] = amount * 100;
        vnp_Params['vnp_ReturnUrl'] = returnUrl;
        vnp_Params['vnp_IpAddr'] = ipAddr;
        vnp_Params['vnp_CreateDate'] = createDate;
        let paymentObject = {
            "order_id": orderId,
            "payment_date": new Date(),
            "amount_paid": amount * 100,
            "payment_status": PENDING_PAYMENT_STATUS,
            "vnp_TxnRef": vnp_Params['vnp_TxnRef']
        };
        if (bankCode && bankCode !== '') {
            vnp_Params['vnp_BankCode'] = bankCode;
            paymentObject.vnp_BankCode = bankCode
        }

        vnp_Params = sortObject(vnp_Params);

        let querystring = require('qs');
        let signData = querystring.stringify(vnp_Params, {
            encode: false
        });
        let crypto = require("crypto");
        let hmac = crypto.createHmac("sha512", secretKey);
        let signed = hmac.update(new Buffer(signData, 'utf-8')).digest("hex");
        vnp_Params['vnp_SecureHash'] = signed;
        vnpUrl += '?' + querystring.stringify(vnp_Params, {
            encode: false
        });
        console.log(vnpUrl);
        //save payment to database
        const paymentseService = new ItemsService('payment', {
            accountability: req.accountability,
            schema: req.schema
        });
        const payment = await paymentseService.createOne(paymentObject);
        res.status(200).json({
            data: {
                redirectUrl: vnpUrl
            }
        });
        // res.redirect(vnpUrl);
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


function sortObject(obj) {
    let sorted = {};
    let str = [];
    let key;
    for (key in obj) {
        if (obj.hasOwnProperty(key)) {
            str.push(encodeURIComponent(key));
        }
    }
    str.sort();
    for (key = 0; key < str.length; key++) {
        sorted[str[key]] = encodeURIComponent(obj[str[key]]).replace(/%20/g, "+");
    }
    return sorted;
}