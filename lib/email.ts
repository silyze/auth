import { createTransport } from "nodemailer";
import { EmailConfig } from "./config";

type EmailTemplateParams<TUserMetadata> = {
  reset: {
    jwt: string;
  } & TUserMetadata;
  verify: {
    jwt: string;
  } & TUserMetadata;
};

export type EmailTemplates<TUserMetadata> = {
  [T in keyof EmailTemplateParams<TUserMetadata>]: (
    params: EmailTemplateParams<TUserMetadata>[T]
  ) => {
    subject: string;
    html: string;
    text: string;
  };
};

async function sendEmail<
  TUserMetadata,
  T extends keyof EmailTemplateParams<TUserMetadata>
>(
  config: EmailConfig<TUserMetadata>,
  email: string,
  type: T,
  params: EmailTemplateParams<TUserMetadata>[T]
) {
  if (config.smtp === false) {
    const mail = { ...config.templates[type](params), to: email };
    return config.sendMessage(mail);
  }
  const transport = createTransport({
    port: config.smtp.SMTP_PORT,
    host: config.smtp.SMTP_HOST,
    auth: {
      user: config.smtp.SMTP_EMAIL,
      pass: config.smtp.SMTP_PASSWORD,
    },
  });

  const mail = config.templates[type](params);
  return new Promise<void>((resolve, reject) =>
    transport.sendMail(
      {
        to: email,
        from: process.env.SMTP_EMAIL,
        text: mail.text,
        html: mail.html,
        subject: mail.subject,
      },
      (err) => {
        if (err) {
          reject(err);
        }
        resolve();
      }
    )
  );
}

export class EmailService<TUserMetadata> {
  #config: EmailConfig<TUserMetadata>;
  constructor(config: EmailConfig<TUserMetadata>) {
    this.#config = config;
  }

  send<T extends keyof EmailTemplateParams<TUserMetadata>>(
    email: string,
    type: T,
    params: EmailTemplateParams<TUserMetadata>[T]
  ) {
    return sendEmail<TUserMetadata, T>(this.#config, email, type, params);
  }
}
