import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";

const firebaseConfig = {
  apiKey: "AIzaSyDa42wdeZOLr3dpT2jxK2wv0zlhMeCgxcs",
  authDomain: "secscan-tesis.firebaseapp.com",
  projectId: "secscan-tesis",
  storageBucket: "secscan-tesis.firebasestorage.app",
  messagingSenderId: "84828357667",
  appId: "1:84828357667:web:3c0d72b5bd4c94c8589d96",
  measurementId: "G-73F972TZ1X"
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();

googleProvider.setCustomParameters({
  prompt: 'select_account'
});
