// const nodemailer =require("nodemailer");

// const sendEmail = async (subject, message, send_to, sent_from, reply_to) => {
//   const transporter = nodemailer.createTransport({
//     host: process.env.EMAIL_HOST,
//     port: "587",
//     auth: {
//       user: process.env.EMAIL_USER,
//       pass: process.env.EMAIL_PASS,
//     },
//     tls: {
//       rejectUnauthorized: false,
//     },
//   });

//   const options = {
//     from: sent_from,
//     to: send_to,
//     replyTo: reply_to,
//     subject: subject,
//     html: message,
//   };

//   // Send Email
//   transporter.sendMail(options, function (err, info) {
//     if (err) {
//       console.log(err);
//     } else {
//       console.log(info);
//     }
//   });
// };
// module.exports =sendEmail;
const nodemailer = require("nodemailer");

const sendEmail = async (subject, message, send_to, sent_from, reply_to) => {
  try {
    // Create a transporter
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: 587, // Port should be a number, not a string
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

    // Mail options
    const options = {
      from: sent_from,
      to: send_to,
      replyTo: reply_to,
      subject: subject,
      html: message, // Assuming message is an HTML string
    };

    // Send email
    const info = await transporter.sendMail(options);
    console.log("Email sent: " + info.response); // Log success
    return info; // Return the response info
  } catch (err) {
    console.error("Error sending email: ", err);
    throw new Error("Email not sent"); // Throw error for better error handling
  }
};

module.exports = sendEmail;
