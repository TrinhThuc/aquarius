import {
    PAYMENT_STATUS
} from '../common/paymentStatus'

const SUCCESS_PAYMENT_STATUS = '00';
const ERROR_PAYMENT_STATUS = '23';
const PROCESSING_STATUS = '02';

export async function vnpayReturn(req, res, services, exceptions, database, env) {
    const {
        ItemsService
    } = services;
    const {
        ServiceUnavailableException,
        InvalidQueryException
    } = exceptions;
    console.log(database);
    try {
        let vnp_Params = req.query;
        console.log(vnp_Params);
        let secureHash = vnp_Params['vnp_SecureHash'];

        delete vnp_Params['vnp_SecureHash'];
        delete vnp_Params['vnp_SecureHashType'];

        vnp_Params = sortObject(vnp_Params);

        let tmnCode = env['vnp_TmnCode'];
        let secretKey = env['vnp_HashSecret'];

        let querystring = require('qs');
        let signData = querystring.stringify(vnp_Params, {
            encode: false
        });
        let crypto = require("crypto");
        let hmac = crypto.createHmac("sha512", secretKey);
        let signed = hmac.update(new Buffer(signData, 'utf-8')).digest("hex");
        const paymentseService = new ItemsService('payment', {
            accountability: req.accountability,
            schema: req.schema
        });
        const orderService = new ItemsService('order', {
            accountability: req.accountability,
            schema: req.schema
        });
        if (secureHash === signed) {
            const paymentCheck = await paymentseService.readByQuery({
                fields: ["*"],
                filter: {
                    vnp_TxnRef: {
                        _eq: vnp_Params['vnp_TxnRef'],
                    },
                }
            })
            if (!paymentCheck || paymentCheck.length === 0) {
                throw new InvalidQueryException("Invalid request")
            }
            const desiredCode = vnp_Params['vnp_ResponseCode'];
            let desiredStatus;
            for (const statusKey in PAYMENT_STATUS) {
                if (PAYMENT_STATUS.hasOwnProperty(statusKey) && PAYMENT_STATUS[statusKey].code === desiredCode) {
                    desiredStatus = PAYMENT_STATUS[statusKey];
                    break;
                }
            }
            let updateObject = {
                payment_status_code: vnp_Params['vnp_ResponseCode'],
                payment_status_message: desiredStatus.message,
                vnp_TransactionNo: vnp_Params['vnp_TransactionNo'],
                vnp_BankCode: vnp_Params['vnp_BankCode']
            }
            let orderObject = {}
            if (desiredCode === PAYMENT_STATUS.SUCCESS.code) {
                updateObject.payment_status = PROCESSING_STATUS;
                orderObject.order_status = PROCESSING_STATUS;
            } else {
                orderObject.order_status = ERROR_PAYMENT_STATUS;
            }
            await orderService.updateOne(paymentCheck[0].order_id, orderObject);
            const payment = await paymentseService.updateOne(paymentCheck[0].id, updateObject);
            //Kiem tra xem du lieu trong db co hop le hay khong va thong bao ket qua
            res.cookie('vnp_ResponseCode', JSON.stringify({
                vnp_TxnRef: vnp_Params['vnp_TxnRef'],
                code: vnp_Params['vnp_ResponseCode']
            }), {
                maxAge: 900000,
                httpOnly: true
            });
            // res.status(200).json({
            //     code: vnp_Params['vnp_ResponseCode']
            // })
        } else {
            const payment = await paymentseService.updateOne(paymentCheck[0].id, {
                payment_status: PAYMENT_STATUS.ERROR.code
            });
            await orderService.updateOne(paymentCheck[0].order_id, {

            });
            res.cookie('vnp_ResponseCode', JSON.stringify({
                vnp_TxnRef: vnp_Params['vnp_TxnRef'],
                code: '97'
            }), {
                maxAge: 900000,
                httpOnly: true
            });
            // res.status(200).json({
            //     code: '97'
            // });
        }
        res.redirect(env['FRONTEND_REDIRECT_PAYMENT_URL']);
    } catch (error) {
        console.log(error);
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