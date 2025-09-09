import swaggerAutogen from 'swagger-autogen';

const outputFile='./swagger.json';
const endPointsFiles = ['./index.js'];

const doc={
    info:{
        title:'API del proyecto ANIMALBEATS',
        description: 'Esta API permite llevar el control completo del proyecto AnimalBeats'
    },
    host: 'localhost:3000',
    schemes: ['http']
}

swaggerAutogen()(outputFile, endPointsFiles,doc);