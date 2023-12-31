import nodemailer from 'nodemailer';
import QRCode from 'qrcode';
import {
	replaceEmailTemplate,
	replaceTicketTemplate
} from './template/mailTemplate'

const PROCESSING_PAYMENT_STATUS = '02';
const PENDING_PAYMENT_STATUS = '05';
const SUCCESS_PAYMENT_STATUS = '00';
const TICKET_TYPE_ADULT = 'ADULT';
const TICKET_TYPE_CHILD = 'CHILD'
export default ({
	action,
}, {
	services,
	env
}) => {
	const {
		ItemsService
	} = services;
	action('payment.items.update', async (keys, collection) => {
		try {
			if (!keys.payload.payment_status || keys.payload.payment_status !== PROCESSING_PAYMENT_STATUS) {
				return;
			}
			const paymentService = new ItemsService('payment', {
				accountability: collection.accountability,
				schema: collection.schema
			});
			const orderService = new ItemsService('order', {
				accountability: collection.accountability,
				schema: collection.schema
			});
			const payment = await paymentService.readOne(keys.keys[0], {
				fields: ["*", "order_id.*", "order_id.pool_id.*", "order_id.tickets.*", "order_id.tickets.ticket_id.*"]
			});
			if (!payment) {
				console.log("Not exits payment");
				return;
			}
			const transporter = nodemailer.createTransport({
				host: 'smtp.gmail.com',
				port: 587,
				service: 'gmail',
				auth: {
					user: env['EMAIL_SENDMAIL_USER'],
					pass: env['EMAIL_SENDMAIL_PASSWORD']
				}
			});

			console.log(payment);
			const url = env['PUBLIC_URL'] + `/checkin/order/${payment.order_id.id}`; // Thay thế bằng URL hoặc dữ liệu cụ thể của bạn
			const qrCodeOptions = {
				margin: 3,
				errorCorrectionLevel: 'H', // Độ chống lỗi cao
				version: 6, // Phiên bản mã QR (từ 1 đến 40, càng cao càng chi tiết)
				scale: 8, // Tăng tỷ lệ để có hình ảnh chi tiết hơn
			};
			const qrCodeDataUrl = await QRCode.toDataURL(url, qrCodeOptions);

			console.log(qrCodeDataUrl);
			const email_receiver = payment.order_id.email_receiver;
			if (!email_receiver || !validateEmail(email_receiver)) {
				console.log("Email invalid");
				return;
			}


			const phone_number_receiver = payment.order_id.phone_number_receiver;
			const vnp_TxnRef = payment.vnp_TxnRef;
			const payment_date = formatDateTime(payment.payment_date);
			const pool_name = payment.order_id.pool_id.name;
			const total_amount = payment.order_id.total_amount;
			const ticketLst = payment.order_id.tickets;

			let tickets_detail = '';
			if (ticketLst) {
				ticketLst.forEach((ticket, index) => {
					let ticket_description = `${ticket.ticket_id.ticket_name} tại ${payment.order_id.pool_id.name} có hạn sử dụng trong ngày ${ticket.date_available}`
					let ticketObject = {
						ticket_name: ticket.ticket_id.ticket_name,
						numerical_order: index + 1,
						ticket_description: ticket_description,
						price: formatAmount(ticket.ticket_id.price)
					}
					let ticketTemplate = replaceTicketTemplate(ticketObject);
					tickets_detail += ticketTemplate;
				});

			}
			let emailObject = {
				email_receiver: email_receiver,
				phone_number_receiver: phone_number_receiver,
				vnp_TxnRef: vnp_TxnRef,
				payment_date: payment_date,
				pool_name: pool_name,
				total_amount: formatAmount(total_amount),
				tickets_detail: tickets_detail
			}
			let emailTemplate = replaceEmailTemplate(emailObject);

			const mailConfigurations = {
				from: env['EMAIL_SENDMAIL_USER'],
				to: email_receiver,
				subject: '[AQUARIUS] Mã vé bể bơi',
				// attachDataUrls: true,
				html: emailTemplate,
				attachments: [{
					filename: 'qrCodeImage.png',
					content: qrCodeDataUrl.split(',')[1],
					encoding: 'base64',
					cid: 'qrCodeImage',
				}, ],
			};

			transporter.sendMail(mailConfigurations, function (error, info) {
				if (error) throw Error(error);
				console.log('Email Sent Successfully');
				console.log(info);
			});

			await paymentService.updateOne(keys.keys[0], {
				payment_status: SUCCESS_PAYMENT_STATUS
			});
			await orderService.updateOne(payment.order_id.id, {
				order_status: SUCCESS_PAYMENT_STATUS
			});
		} catch (error) {
			console.log(error);
		}
	});
};


function validateEmail(email) {
	const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	return regex.test(email);
}

function formatDateTime(inputDateTime) {
	const dateObj = new Date(inputDateTime);

	const year = dateObj.getFullYear();
	const month = (dateObj.getMonth() + 1).toString().padStart(2, '0');
	const day = dateObj.getDate().toString().padStart(2, '0');
	const hours = dateObj.getHours().toString().padStart(2, '0');
	const minutes = dateObj.getMinutes().toString().padStart(2, '0');
	const seconds = dateObj.getSeconds().toString().padStart(2, '0');

	const formattedDateTime = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;

	return formattedDateTime;
}

function formatAmount(amount) {
	return amount.toLocaleString('en-US');
}