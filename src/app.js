const { GoogleGenerativeAI } = require("@google/generative-ai");
const { getAuthUrl, getTokenFromCode, firstInteraction } = require('../backend/authv2')
const twilio = require('twilio');
const express = require('express');
const validateEnvParam = require("../backend/middleware/verifyTwilioRequest");
const { createJwtToken } = require("../backend/middleware/jwt");
const router = express.Router();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

const modelName = "gemini-1.5-pro";

const functions = {
    // calendar

    createEvent: async ({ token, summary, location, description, startDateTime, endDateTime, timeZone, attendees }) => {

        const url = `https://botwo-38304355066.us-central1.run.app/calendar/create`
        const payload = {
            summary,
            location,
            description,
            startDateTime,
            endDateTime,
            timeZone,
            attendees
        }
        const res = await fetch(url, {
            method: "POST",
            body: JSON.stringify(payload),
            headers: {
                Authorization: 'Bearer ' + token,
                "Content-Type": "application/json"
            }
        })

        const data = await res.json();

        return data
    },

    //anda
    listEvents: async ({ token }) => {
        const url = `https://botwo-38304355066.us-central1.run.app/calendar/list`
        const res = await fetch(url, {
            method: "GET",
            headers: {
                Authorization: 'Bearer ' + token
            }
        })

        const data = await res.json();

        return data
    },
    //anda
    checkAvailability: async ({ token, email, startDate, endDate }) => {

        const res = await fetch('https://botwo-38304355066.us-central1.run.app/calendar/availability', {
            method: 'POST',
            body: JSON.stringify({
                "email": email,
                "startDate": startDate,
                "endDate": endDate
            }),
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })

        const data = await res.json()

        return data
    },
    //anda
    cancelEvent: async ({ token, eventName, eventDate }) => {

        const res = await fetch('https://botwo-38304355066.us-central1.run.app/calendar/cancel', {
            method: 'POST',
            body: JSON.stringify({
                "eventName": eventName,
                "eventDate": eventDate
            }),
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })

        const data = await res.json()

        return data
    },
    // REVISAR
    modifyEvent: async ({ token, eventName, eventDate, updatedFields, participants = [], removeParticipants = false }) => {
        const payload = JSON.stringify({
            eventName, eventDate, updatedFields, participants, removeParticipants
        })

        const res = await fetch('https://botwo-38304355066.us-central1.run.app/calendar/modify', {
            method: 'POST',
            body: payload,
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })

        const data = await res.json()

        return data
    },

    // drive
    // anda
    uploadToDrive: async ({ token, url, filename }) => {
        const res = await fetch("https://botwo-38304355066.us-central1.run.app/drive/upload", {
            method: "POST",
            body: JSON.stringify({ url, filename }),
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })

        return res;
    },

    //anda
    deleteFromDrive: async ({ token, searchTerm }) => {
        const res = await fetch(`https://botwo-38304355066.us-central1.run.app/drive/delete?searchTerm=${searchTerm}`, {
            method: "GET",
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })

        return res;
    },

    // anda
    searchInDrive: async ({ token, searchTerm }) => {
        const res = await fetch(`https://botwo-38304355066.us-central1.run.app/drive/list?searchTerm=${searchTerm}`, {
            method: "GET",
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })
        const data = await res.json()
        return data;
    },

    // translate
    // anda
    getLanguageCode: async ({ text, language }) => {
        const languages = [
            { nombre: "Afrikaans", nombre_en: "Afrikaans", codigo: "af" },
            { nombre: "Albanes", nombre_en: "Albanian", codigo: "sq" },
            { nombre: "Amarico", nombre_en: "Amharic", codigo: "am" },
            { nombre: "Arabe", nombre_en: "Arabic", codigo: "ar" },
            { nombre: "Armenio", nombre_en: "Armenian", codigo: "hy" },
            { nombre: "Asames", nombre_en: "Assamese", codigo: "as" },
            { nombre: "Aimara", nombre_en: "Aymara", codigo: "ay" },
            { nombre: "Azerbaiyano", nombre_en: "Azerbaijani", codigo: "az" },
            { nombre: "Bambara", nombre_en: "Bambara", codigo: "bm" },
            { nombre: "Euskara", nombre_en: "Basque", codigo: "eu" },
            { nombre: "Bielorruso", nombre_en: "Belarusian", codigo: "be" },
            { nombre: "Bengali", nombre_en: "Bengali", codigo: "bn" },
            { nombre: "Bhojpuri", nombre_en: "Bhojpuri", codigo: "bho" },
            { nombre: "Bosnio", nombre_en: "Bosnian", codigo: "bs" },
            { nombre: "Bulgaro", nombre_en: "Bulgarian", codigo: "bg" },
            { nombre: "Catalan", nombre_en: "Catalan", codigo: "ca" },
            { nombre: "Cebuano", nombre_en: "Cebuano", codigo: "ceb" },
            { nombre: "Chino (simplificado)", nombre_en: "Chinese (Simplified)", codigo: "zh-CN" },
            { nombre: "Chino (tradicional)", nombre_en: "Chinese (Traditional)", codigo: "zh-TW" },
            { nombre: "Corso", nombre_en: "Corsican", codigo: "co" },
            { nombre: "Croata", nombre_en: "Croatian", codigo: "hr" },
            { nombre: "Checo", nombre_en: "Czech", codigo: "cs" },
            { nombre: "Danes", nombre_en: "Danish", codigo: "da" },
            { nombre: "Dhivehi", nombre_en: "Dhivehi", codigo: "dv" },
            { nombre: "Dogri", nombre_en: "Dogri", codigo: "doi" },
            { nombre: "Holandes", nombre_en: "Dutch", codigo: "nl" },
            { nombre: "Ingles", nombre_en: "English", codigo: "en" },
            { nombre: "Esperanto", nombre_en: "Esperanto", codigo: "eo" },
            { nombre: "Estonio", nombre_en: "Estonian", codigo: "et" },
            { nombre: "Ewe", nombre_en: "Ewe", codigo: "ee" },
            { nombre: "Filipino (tagalo)", nombre_en: "Filipino (Tagalog)", codigo: "fil" },
            { nombre: "Finlandes", nombre_en: "Finnish", codigo: "fi" },
            { nombre: "Frances", nombre_en: "French", codigo: "fr" },
            { nombre: "Frison", nombre_en: "Frisian", codigo: "fy" },
            { nombre: "Galego", nombre_en: "Galician", codigo: "gl" },
            { nombre: "Georgiano", nombre_en: "Georgian", codigo: "ka" },
            { nombre: "Aleman", nombre_en: "German", codigo: "de" },
            { nombre: "Griego", nombre_en: "Greek", codigo: "el" },
            { nombre: "Guarani", nombre_en: "Guarani", codigo: "gn" },
            { nombre: "Gujarati", nombre_en: "Gujarati", codigo: "gu" },
            { nombre: "Criollo haitiano", nombre_en: "Haitian Creole", codigo: "ht" },
            { nombre: "Hausa", nombre_en: "Hausa", codigo: "ha" },
            { nombre: "Hawaiano", nombre_en: "Hawaiian", codigo: "haw" },
            { nombre: "Hebreo", nombre_en: "Hebrew", codigo: "he" },
            { nombre: "Hindi", nombre_en: "Hindi", codigo: "hi" },
            { nombre: "Hmong", nombre_en: "Hmong", codigo: "hmn" },
            { nombre: "Hungaro", nombre_en: "Hungarian", codigo: "hu" },
            { nombre: "Islandes", nombre_en: "Icelandic", codigo: "is" },
            { nombre: "Igbo", nombre_en: "Igbo", codigo: "ig" },
            { nombre: "Ilocano", nombre_en: "Ilocano", codigo: "ilo" },
            { nombre: "Indonesio", nombre_en: "Indonesian", codigo: "id" },
            { nombre: "Irlandes", nombre_en: "Irish", codigo: "ga" },
            { nombre: "Italiano", nombre_en: "Italian", codigo: "it" },
            { nombre: "Japones", nombre_en: "Japanese", codigo: "ja" },
            { nombre: "Javanes", nombre_en: "Javanese", codigo: "jv" },
            { nombre: "Canares", nombre_en: "Kannada", codigo: "kn" },
            { nombre: "Kazajo", nombre_en: "Kazakh", codigo: "kk" },
            { nombre: "Jemer", nombre_en: "Khmer", codigo: "km" },
            { nombre: "Kiñarwanda", nombre_en: "Kinyarwanda", codigo: "rw" },
            { nombre: "Konkani", nombre_en: "Konkani", codigo: "gom" },
            { nombre: "Coreano", nombre_en: "Korean", codigo: "ko" },
            { nombre: "Krio", nombre_en: "Krio", codigo: "kri" },
            { nombre: "Kurdo", nombre_en: "Kurdish", codigo: "ku" },
            { nombre: "Kurdo (Sorani)", nombre_en: "Kurdish (Sorani)", codigo: "ckb" },
            { nombre: "Kirguizo", nombre_en: "Kyrgyz", codigo: "ky" },
            { nombre: "Laosiano", nombre_en: "Lao", codigo: "lo" },
            { nombre: "Latin", nombre_en: "Latin", codigo: "la" },
            { nombre: "Leton", nombre_en: "Latvian", codigo: "lv" },
            { nombre: "Lingala", nombre_en: "Lingala", codigo: "ln" },
            { nombre: "Lituano", nombre_en: "Lithuanian", codigo: "lt" },
            { nombre: "Luganda", nombre_en: "Luganda", codigo: "lg" },
            { nombre: "Luxemburgues", nombre_en: "Luxembourgish", codigo: "lb" },
            { nombre: "Macedonio", nombre_en: "Macedonian", codigo: "mk" },
            { nombre: "Maithili", nombre_en: "Maithili", codigo: "mai" },
            { nombre: "Malgache", nombre_en: "Malagasy", codigo: "mg" },
            { nombre: "Malayo", nombre_en: "Malay", codigo: "ms" },
            { nombre: "Malayalam", nombre_en: "Malayalam", codigo: "ml" },
            { nombre: "Maltes", nombre_en: "Maltese", codigo: "mt" },
            { nombre: "Maori", nombre_en: "Maori", codigo: "mi" },
            { nombre: "Marathi", nombre_en: "Marathi", codigo: "mr" },
            { nombre: "Meiteilon (manipuri)", nombre_en: "Meiteilon (Manipuri)", codigo: "mni-Mtei" },
            { nombre: "Mizo", nombre_en: "Mizo", codigo: "lus" },
            { nombre: "Mongol", nombre_en: "Mongolian", codigo: "mn" },
            { nombre: "Birmano", nombre_en: "Burmese", codigo: "my" },
            { nombre: "Nepali", nombre_en: "Nepali", codigo: "ne" },
            { nombre: "Noruego", nombre_en: "Norwegian", codigo: "no" },
            { nombre: "Nyanja (Chichewa)", nombre_en: "Nyanja (Chichewa)", codigo: "ny" },
            { nombre: "Odia (oriya)", nombre_en: "Odia (Oriya)", codigo: "or" },
            { nombre: "Oromo", nombre_en: "Oromo", codigo: "om" },
            { nombre: "Pastun", nombre_en: "Pashto", codigo: "ps" },
            { nombre: "Persa", nombre_en: "Persian", codigo: "fa" },
            { nombre: "Polaco", nombre_en: "Polish", codigo: "pl" },
            { nombre: "Portugues", nombre_en: "Portuguese", codigo: "pt" },
            { nombre: "Panyabi", nombre_en: "Punjabi", codigo: "pa" },
            { nombre: "Quechua", nombre_en: "Quechua", codigo: "qu" },
            { nombre: "Rumano", nombre_en: "Romanian", codigo: "ro" },
            { nombre: "Ruso", nombre_en: "Russian", codigo: "ru" },
            { nombre: "Samoano", nombre_en: "Samoan", codigo: "sm" },
            { nombre: "Sanscrito", nombre_en: "Sanskrit", codigo: "sa" },
            { nombre: "Gaelico escoces", nombre_en: "Scottish Gaelic", codigo: "gd" },
            { nombre: "Sepedi", nombre_en: "Sepedi", codigo: "nso" },
            { nombre: "Serbio", nombre_en: "Serbian", codigo: "sr" },
            { nombre: "Sesoto", nombre_en: "Sesotho", codigo: "st" },
            { nombre: "Shona", nombre_en: "Shona", codigo: "sn" },
            { nombre: "Sindhi", nombre_en: "Sindhi", codigo: "sd" },
            { nombre: "Cingales", nombre_en: "Sinhala", codigo: "si" },
            { nombre: "Eslovaco", nombre_en: "Slovak", codigo: "sk" },
            { nombre: "Esloveno", nombre_en: "Slovenian", codigo: "sl" },
            { nombre: "Somali", nombre_en: "Somali", codigo: "so" },
            { nombre: "Español", nombre_en: "Spanish", codigo: "es" },
            { nombre: "Sundanes", nombre_en: "Sundanese", codigo: "su" },
            { nombre: "Swahili", nombre_en: "Swahili", codigo: "sw" },
            { nombre: "Sueco", nombre_en: "Swedish", codigo: "sv" },
            { nombre: "Tagalo (filipino)", nombre_en: "Tagalog (Filipino)", codigo: "tl" },
            { nombre: "Tayiko", nombre_en: "Tajik", codigo: "tg" },
            { nombre: "Tamil", nombre_en: "Tamil", codigo: "ta" },
            { nombre: "Tartaro", nombre_en: "Tatar", codigo: "tt" },
            { nombre: "Telugu", nombre_en: "Telugu", codigo: "te" },
            { nombre: "Tailandes", nombre_en: "Thai", codigo: "th" },
            { nombre: "Tigrinya", nombre_en: "Tigrinya", codigo: "ti" },
            { nombre: "Tsonga", nombre_en: "Tsonga", codigo: "ts" },
            { nombre: "Turco", nombre_en: "Turkish", codigo: "tr" },
            { nombre: "Turkmeno", nombre_en: "Turkmen", codigo: "tk" },
            { nombre: "Twi (Akan)", nombre_en: "Twi (Akan)", codigo: "ak" },
            { nombre: "Ucraniano", nombre_en: "Ukrainian", codigo: "uk" },
            { nombre: "Urdu", nombre_en: "Urdu", codigo: "ur" },
            { nombre: "Uigur", nombre_en: "Uyghur", codigo: "ug" },
            { nombre: "Uzbeko", nombre_en: "Uzbek", codigo: "uz" },
            { nombre: "Vietnamita", nombre_en: "Vietnamese", codigo: "vi" },
            { nombre: "Gales", nombre_en: "Welsh", codigo: "cy" },
            { nombre: "Xhosa", nombre_en: "Xhosa", codigo: "xh" },
            { nombre: "Yiddish", nombre_en: "Yiddish", codigo: "yi" },
            { nombre: "Yoruba", nombre_en: "Yoruba", codigo: "yo" },
            { nombre: "Zulu", nombre_en: "Zulu", codigo: "zu" }
        ];

        const code = languages.find(l => language.toLowerCase() === l.nombre.toLowerCase() || language.toLowerCase() === l.nombre_en.toLowerCase() || language === l.codigo)
        const payload = {
            text,
            code: code.codigo
        }

        const res = await fetch("https://botwo-38304355066.us-central1.run.app/translate", {
            method: "POST",
            body: JSON.stringify(payload),
            headers: {
                "Content-Type": "application/json"
            }
        })

        const data = await res.json()
        return data
    },

    // create meet
    // anda
    createMeet: async ({ token }) => {
        const res = await fetch("https://botwo-38304355066.us-central1.run.app/meet/create", {
            method: "POST",
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })

        const data = await res.json()

        return data;
    },

    // gmail
    // anda
    sendEmail: async ({ token, addressees, subject, text }) => {

        const payload = {
            "addressees": addressees,
            "subject": subject,
            "text": text
        }
        const res = await fetch("https://botwo-38304355066.us-central1.run.app/gmail/send", {
            method: "POST",
            body: JSON.stringify(payload),
            headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + token,
            }
        })

        const data = await res.json()

        return data;
    },

    // anda
    searchEmail: async ({ token, searchTerm }) => {
        const res = await fetch(`https://botwo-38304355066.us-central1.run.app/gmail/search?searchTerm=${searchTerm}`, {
            method: "GET",
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })
        const data = await res.json()
        return data;
    },

    // anda
    listUnread: async ({ token }) => {
        const res = await fetch(`https://botwo-38304355066.us-central1.run.app/gmail/list`, {
            method: "GET",
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })
        const data = await res.json()
        return data;
    },

    // revisar
    marksAllEmailsAsRead: async ({ token }) => {
        const res = await fetch(`https://botwo-38304355066.us-central1.run.app/gmail/markAsRead`, {
            method: "GET",
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })
        const data = await res.json()
        return data;
    },

    // photos
    // anda
    extractTextFromPhoto: async ({ token, url }) => {
        const res = await fetch(`https://botwo-38304355066.us-central1.run.app/photos/extractText`, {
            method: "POST",
            body: JSON.stringify({ url }),
            headers: {
                Authorization: "Bearer " + token,
                "Content-Type": "application/json"
            }
        })
        const data = await res.json()
        return data;
    },

};

const generativeModel = genAI.getGenerativeModel({
    model: modelName,
    tools: {
        functionDeclarations: [
            // calendar
            {
                name: "createEvent",
                description: "Creates a new event in the user's Google Calendar",
                parameters: {
                    type: "OBJECT",
                    description: "Details required to create a calendar event",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "User's auth token for authorization",
                        },
                        summary: {
                            type: "STRING",
                            description: "Event title or summary (required)",
                        },
                        location: {
                            type: "STRING",
                            description: "Location of the event",
                        },
                        description: {
                            type: "STRING",
                            description: "Description of the event",
                        },
                        startDateTime: {
                            type: "STRING",
                            description: "Start date and time in ISO format (e.g., 2024-12-01T09:00:00-03:00, required)",
                        },
                        endDateTime: {
                            type: "STRING",
                            description: "End date and time in ISO format (e.g., 2024-12-01T17:00:00-03:00, required)",
                        },
                        timeZone: {
                            type: "STRING",
                            description: "Time zone for the event (e.g., America/Buenos_Aires, defaults to GMT)",
                        },
                        attendees: {
                            type: "ARRAY",
                            description: "List of attendees' emails",
                            items: {
                                type: "STRING",
                            },
                        },
                    },
                    required: ["token", "summary", "startDateTime", "endDateTime"],
                },
            }
            ,
            {
                name: "listEvents",
                description: "Provides information about upcoming events in the user's google calendar",
                parameters: {
                    type: "OBJECT",
                    description: "user auth token",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token with user info",
                        },
                    },
                    required: ["token"],
                },
            },
            {
                name: "checkAvailability",
                description: "provides information about the availability of someone else's calendar based on email address",
                parameters: {
                    type: "OBJECT",
                    description: "Info for request",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token",
                        },
                        email: {
                            type: "STRING",
                            description: "email address to ckeck availability",
                        },
                        startDate: {
                            type: "STRING",
                            description: "start date to query in ISO format, if no time is specified, set it by default to 0 hours, example: 2024-12-01T00:00:00-03:00",
                        },
                        endDate: {
                            type: "STRING",
                            description: "end date to be consulted in ISO format; if not specified, the same day as startDate is used but with the latest time. example 2024-12-01T23:00:00-03:00",
                        },
                    },
                    required: ["token", "email", "startDate", "endDate"],
                },
            },
            {
                name: "modifyEvent",
                description: "Modifies an event in the user's Google Calendar by updating its fields or managing participants.",
                parameters: {
                    type: "object",
                    properties: {
                        token: {
                            type: "string",
                            description: "User's phone number associated with the Google Calendar account.",
                        },
                        eventName: {
                            type: "string",
                            description: "Name of the event to be modified.",
                        },
                        eventDate: {
                            type: "string",
                            description: "Date of the event in the format YYYY-MM-DD.",
                        },
                        updatedFields: {
                            type: "object",
                            description: "Fields to update in the event.",
                            properties: {
                                summary: {
                                    type: "string",
                                    description: "New title or summary of the event.",
                                },
                                start: {
                                    type: "object",
                                    description: "New start date and time of the event.",
                                    properties: {
                                        dateTime: {
                                            type: "string",
                                            description: "Start date and time in ISO 8601 format (e.g., 2024-12-01T15:00:00-03:00).",
                                        },
                                    },
                                    required: ["dateTime"],
                                },
                                end: {
                                    type: "object",
                                    description: "New end date and time of the event.",
                                    properties: {
                                        dateTime: {
                                            type: "string",
                                            description: "End date and time in ISO 8601 format (e.g., 2024-12-01T16:00:00-03:00).",
                                        },
                                    },
                                    required: ["dateTime"],
                                },
                                location: {
                                    type: "string",
                                    description: "New location of the event.",
                                },
                            },
                        },
                        participants: {
                            type: "array",
                            description: "List of emails of participants to add or remove.",
                            items: {
                                type: "string",
                                description: "Email address of a participant.",
                            },
                        },
                        removeParticipants: {
                            type: "boolean",
                            description: "Flag to indicate if participants should be removed instead of added.",
                        },
                    },
                    required: ["token", "eventName", "eventDate", "participants"],
                },
            },
            {
                name: "cancelEvent",
                description: "cancels an event from the user's google calendar",
                parameters: {
                    type: "OBJECT",
                    description: "Info for request",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token",
                        },
                        eventName: {
                            type: "STRING",
                            description: "name/subject of the event",
                        },
                        eventDate: {
                            type: "STRING",
                            description: "event date in format 'yyyy-mm-dd', if the year is not specified use the current year",
                        },
                    },
                    required: ["token", "eventName", "eventDate"],
                },
            },

            // drive
            {
                name: "uploadToDrive",
                parameters: {
                    type: "OBJECT",
                    description: "function to upload a file to google drive",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token",
                        },
                        url: {
                            type: "STRING",
                            description: "file url",
                        },
                        filename: {
                            type: "STRING",
                            description: "name of the file to be uploaded, if it has spaces, please contain them with “_”.",
                        },
                    },
                    required: ["token", "url"],
                },
            },
            {
                name: "deleteFromDrive",
                parameters: {
                    type: "OBJECT",
                    description: "function to delete a file from google drive",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token",
                        },
                        searchTerm: {
                            type: "STRING",
                            description: "filename to search",
                        },
                    },
                    required: ["token", "searchTerm"],
                },
            },
            {
                name: "searchInDrive",
                parameters: {
                    type: "OBJECT",
                    description: "function to search more than one file from google drive, include in your answer the results obtained from the API",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token",
                        },
                        searchTerm: {
                            type: "STRING",
                            description: "term to search",
                        },
                    },
                    required: ["token", "searchTerm"],
                },
            },

            //translate
            {
                name: "getLanguageCode",
                parameters: {
                    type: "OBJECT",
                    description: "Translate language",
                    properties: {
                        text: {
                            type: "STRING",
                            description: "User text to translate",
                        },
                        language: {
                            type: "STRING",
                            description: "Language to translate",
                        },
                    },
                    required: ["text", "language"],
                },
            },

            // meet
            {
                name: "createMeet",
                parameters: {
                    type: "OBJECT",
                    description: "function for create a google meet and return link",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token with user info",
                        },
                    },
                    required: ["token"],
                },
            },

            // gmail
            {
                name: "sendEmail",
                parameters: {
                    type: "OBJECT",
                    description: "function to send a mail via gmail",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token",
                        },
                        subject: {
                            type: "STRING",
                            description: "mail title",
                        },
                        text: {
                            type: "STRING",
                            description: "mail content text",
                        },
                        addressees: {
                            type: "ARRAY",
                            description: "list of recipients",
                            items: {
                                type: "string",
                                description: "Email address of a participant.",
                            },
                        },

                    },
                    required: ["token", "subject", "text", "addressees"],
                },
            },
            {
                name: "searchEmail",
                parameters: {
                    type: "OBJECT",
                    description: "function to search mails in gmail",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token",
                        },
                        searchTerm: {
                            type: "STRING",
                            description: "term to search",
                        },
                    },
                    required: ["token", "searchTerm"],
                },
            },
            {
                name: "listUnread",
                parameters: {
                    type: "OBJECT",
                    description: "function to list unread mails in gmail, reply to the user with the links to access the mails",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token",
                        },
                    },
                    required: ["token"],
                },
            },
            {
                name: "marksAllEmailsAsRead",
                parameters: {
                    type: "OBJECT",
                    description: "function to mark as read all mails in gmail",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token",
                        },
                    },
                    required: ["token"],
                },
            },

            // photos
            {
                name: "extractTextFromPhoto",
                parameters: {
                    type: "OBJECT",
                    description: "function to extract text from a photo",
                    properties: {
                        token: {
                            type: "STRING",
                            description: "auth token",
                        },
                        url: {
                            type: "STRING",
                            description: "photo url",
                        },
                    },
                    required: ["token", "url"],
                },
            },


        ],
    },
});

const init = async (prompt, phone, url = null) => {

    const token = createJwtToken({ phone })

    const chat = generativeModel.startChat();

    prompt = prompt + `\nInclui el token del usuario que es: ${token}` + '\n Ademas, si los resultados de la API incluye enlaces en su respuesta, incluilos para que el usuario pueda acceder facilmente'

    if (url != null) {
        prompt = prompt + `\n La URL del archivo es ${url}, y el token para autenticar la request es ${token}`
    }

    const result = await chat.sendMessage(prompt);

    // console.log(call);

    try {

        const call = result.response.functionCalls()[0];

        const apiResponse = await functions[call.name](call?.args);

        const result2 = await chat.sendMessage([{
            functionResponse: {
                name: 'listEvents',
                response: apiResponse
            }
        }]);

        return result2.response.text()
    } catch (e) {
        return 'Lo siento, por el momento no puedo hacer eso :('
    }
}

router.post('/message', validateEnvParam('AccountSid'), async (req, res) => {

    const twiml = new twilio.twiml.MessagingResponse();

    if (await firstInteraction(req.body.From.toString().split("+549")[1])) {
        const token = createJwtToken({ phone: req.body.From.toString().split("+549")[1] })
        twiml.message(`Bienvenido a Botwo! Para comenzar, inicia sesion en el siguiente enlace: https://botwo-38304355066.us-central1.run.app/auth?token=${token}`);
        res.writeHead(200, { 'Content-Type': 'text/xml' });
        res.end(twiml.toString());
    } else {
        const response = await init(req.body.Body, req.body.From.toString().split("+549")[1], req.body?.MediaUrl0 || null)
        twiml.message(response);
        res.writeHead(200, { 'Content-Type': 'text/xml' });
        res.end(twiml.toString());
    }

});

// Endpoint para iniciar el flujo de autenticación (redirige al usuario a Google para autorizar)
router.get('/auth', (req, res) => {
    const authUrl = getAuthUrl('', `Bearer ${req.query.token}`); // encriptar
    res.redirect(authUrl);
});

// Endpoint de redirección después de la autenticación
router.get('/oauth2callback', async (req, res) => {
    const code = req.query.code;
    const state = req.query.state

    if (!code) {
        return res.status(400).send('No se proporcionó el código de autenticación.');
    }

    try {
        // Intercambia el código de autorización por un access token y un refresh token
        await getTokenFromCode(code, state);
        const { SID, phone } = JSON.parse(Buffer.from(state, 'base64').toString());
        const client = twilio(process.env.TWILIO_USER, process.env.AUTH_TOKEN);
        // Envía un mensaje al usuario a través de Twilio
        await client.messages.create({
            body: 'Te has autenticado correctamente. Disfruta de Botwo!',
            from: 'whatsapp:+14155238886', // Número de Twilio para WhatsApp
            to: `whatsapp:+549${phone}` // Número del usuario (usualmente en formato internacional)
        });

        // Redirige al usuario de vuelta al bot de WhatsApp
        res.redirect(`https://wa.me/+14155238886`);
    } catch (error) {
        console.error('Error al obtener el token:', error);
        res.status(500).send('Error al autenticar');
    }
});

module.exports = router;

