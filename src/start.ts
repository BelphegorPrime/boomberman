import app from './server';

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Boomberman server running on port ${PORT}`);
});
