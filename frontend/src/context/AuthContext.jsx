import { createContext, useContext, useEffect, useState, useCallback } from "react";
import { 
  onAuthStateChanged, 
  signInWithPopup, 
  signOut 
} from "firebase/auth";
import { auth, googleProvider } from "../firebase";

const AuthContext = createContext();

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
      setLoading(false);
    });
    return () => unsubscribe();
  }, []);

  const loginWithGoogle = async () => {
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (error) {
      console.error("Error al iniciar sesión con Google:", error);
      throw error;
    }
  };

  const logout = () => signOut(auth);

  const getToken = useCallback(async () => {
    if (!auth.currentUser) return null;
    return await auth.currentUser.getIdToken();
  }, []);

  return (
    <AuthContext.Provider value={{ user, loginWithGoogle, logout, getToken, loading }}>
      {!loading && children}
    </AuthContext.Provider>
  );
};
