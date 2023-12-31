const EMAIL_TEMPLATE = `
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <style>
        body {
            margin: 0;
            padding: 0;
            background-color: #fff;
        }

        .container {
            width: 100%;
            height: 100%;   
            display: flex;
            flex-direction: column;
        }

        .text {
            padding: 20px;
            background-color: #f2f2f2;
        }

        h1 {
            font-size: 24px;
            font-weight: bold;
        }

        p {
            font-size: 18px;
            line-height: 1.5;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th,
        td {
            border: 1px solid #ccc;
            padding: 10px;
        }

        th {
            font-weight: bold;
        }

        .text>p:first-child {
            margin-top: 0;
        }

        .text>p:last-child {
            margin-bottom: 0;
        }

        img {
            width: 30%;
            max-width: 600px; /* Đảm bảo ảnh không bị quá lớn trên các thiết bị nhỏ */
            height: auto;
            margin: 0 auto; /* Để căn giữa hình ảnh */
            display: block; /* Loại bỏ khoảng trắng dưới hình ảnh */
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="text">
            <h1>AQUARIUS</h1>
            <strong>Thông tin đơn hàng</strong>
            <table>
                <tr>
                    <th>Thông tin thanh toán</th>
                    <th>Thông tin đơn hàng</th>
                </tr>
                <tr>
                    <td>
                        <p>Email: $email_receiver</p>
                        <p>Số điện thoại: $phone_number_receiver</p>
                    </td>
                    <td>
                        <p>Mã đơn hàng: $vnp_TxnRef</p>
                        <p>Thời gian đặt: $payment_date</p>
                    </td>
                </tr>
                <tr>
                    <td>Bể bơi</td>
                    <td>$pool_name</td>
                </tr>
                <tr>
                    <td>Mã giảm giá: Không có</td>
                    <td>Giảm giá: 0</td>
                </tr>
                <tr>
                    <td>Tổng thanh toán: $total_amount</td>
                    <td></td>
                </tr>

            </table>
            <br>
            <br>
            <strong>Chi tiết thông tin vé</strong>
            <table>
                <tr>
                    <th>Loại vé</th>
                    <th>Số lượng</th>
                    <th>Mô tả</th>
                    <th>Đơn giá</th>
                    <th>Thành tiền</th>
                </tr>
                $tickets_detail
            </table>
            <p>Xin vui lòng kiểm tra lại các thông tin trên để đảm bảo tính chính xác. Nếu có bất kỳ sai sót hoặc câu
                hỏi nào, xin hãy liên hệ với chúng tôi qua hotline 0329469366 hoặc qua địa chỉ email
                ticket@aquarius.vn để được hỗ trợ.</p>

            <br>
            <br>
            <strong>Mã vé điện tử (QR)/E-ticket code (QR):</strong>
            <br>
            <img src="cid:qrCodeImage" alt="QR Code">

            <br>
            <br>
            <strong>Ghi chú</strong>
            <p>Đây là vé điện tử, khách hàng vui lòng xuất trình mã này tại các điểm xác nhận vé tại bể bơi.</p>

            <p>Khách hàng có trách nhiệm bảo mật tuyệt đối mã vé điện tử của mình</p>

            <p>Mỗi mã QR tương ứng với một lần đổi vé duy nhất</p>

            <br>
            <br>
            <p>Để xem chi tiết đơn hàng, quý khách vui lòng đăng nhập tài khoản tại trang
                https://ticket.aquarius.vn/, lựa chọn mục Lịch sử mua hàng để theo dõi.</p>
            <p>Để cập nhật các thông tin mới nhất về bể bơi và các hướng dẫn khác, vui lòng
                truy cập website và các trang mạng xã hội của Aquarius</p>
            <p>Xin cảm ơn và chúc bạn có trải nghiệm tuyệt vời cùng Aquarius!</p>
        </div>
    </div>
</body>

</html>
`

const TICKET_TEMPLATE = `
<tr>
    <td>$ticket_name</td>
    <td>$numerical_order</td>
    <td>$ticket_description</td>
    <td>$price</td>
    <td>$price</td>
</tr>`

const replaceTicketTemplate = (data) => {
    let replacedTemplate = TICKET_TEMPLATE;
    replacedTemplate = replacedTemplate.replace('$ticket_name', data.ticket_name);
    replacedTemplate = replacedTemplate.replace('$numerical_order', data.numerical_order);
    replacedTemplate = replacedTemplate.replace('$ticket_description', data.ticket_description);
    replacedTemplate = replacedTemplate.replaceAll('$price', data.price);
    return replacedTemplate;
};

function replaceEmailTemplate(data) {
    let replacedTemplate = EMAIL_TEMPLATE;
    replacedTemplate = replacedTemplate.replace('$email_receiver', data.email_receiver);
    replacedTemplate = replacedTemplate.replace('$phone_number_receiver', data.phone_number_receiver);
    replacedTemplate = replacedTemplate.replace('$vnp_TxnRef', data.vnp_TxnRef);
    replacedTemplate = replacedTemplate.replace('$payment_date', data.payment_date);
    replacedTemplate = replacedTemplate.replace('$pool_name', data.pool_name);
    replacedTemplate = replacedTemplate.replace('$total_amount', data.total_amount);
    replacedTemplate = replacedTemplate.replace('$tickets_detail', data.tickets_detail);
    return replacedTemplate;
}

module.exports = {
    replaceTicketTemplate,
    replaceEmailTemplate
}