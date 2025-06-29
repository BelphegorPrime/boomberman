import { Response } from "express";
import { getRandomFakeResponse } from "../ai/fakeResponseManager";
import { corruptJsonString } from "./corruptJsonString";

export function generateFaultyResponse(res: Response) {
    const variants = ['teapot', 'gibberish', 'malformedJson', 'largePayload'];
    const choice = variants[Math.floor(Math.random() * variants.length)];

    switch (choice) {
        case 'teapot': {
            res.status(418).send("I'm a teapot. 🍵");
            break;
        }

        case 'gibberish': {
            const fakeJson = getRandomFakeResponse();
            res
                .status(200)
                .setHeader('Content-Type', 'application/json')
                .send(fakeJson || {});
            break;
        }

        case 'malformedJson': {
            const fakeJson = getRandomFakeResponse();
            const corrupted = fakeJson ?
                corruptJsonString(JSON.stringify(fakeJson)) :
                '{"message": "Oops", "incomplete": true,, }';

            res
                .status(200)
                .setHeader('Content-Type', 'application/json')
                .send(corrupted);
            break;
        }

        case 'largePayload': {
            const lorem = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. ';
            const hugePayload = lorem.repeat(200_000); // ~10MB
            res.status(200).send(hugePayload);
            break;
        }
    }
}
