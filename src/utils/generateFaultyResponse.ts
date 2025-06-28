import { Response } from "express";

export function generateFaultyResponse(res: Response) {
    const variants = ['teapot', 'malformedJson', 'largePayload'];
    const choice = variants[Math.floor(Math.random() * variants.length)];

    switch (choice) {
        case 'teapot':
            res.status(418).send("I'm a teapot. 🍵");
            break;

        case 'malformedJson':
            res
                .status(200)
                .setHeader('Content-Type', 'application/json')
                .send('{"message": "Oops", "incomplete": true,, }'); // Invalid JSON
            break;

        case 'largePayload':
            const lorem = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. ';
            const hugePayload = lorem.repeat(200_000); // ~10MB
            res.status(200).send(hugePayload);
            break;
    }
}
