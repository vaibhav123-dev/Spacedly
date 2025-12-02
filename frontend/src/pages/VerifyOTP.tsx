import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useAppDispatch } from '@/store/hooks';
import { setCredentials } from '@/store/slices/authSlice';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import { Loader2, Shield } from 'lucide-react';
import { API_BASE_URL } from '@/config/app';

const VerifyOTP = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const dispatch = useAppDispatch();
  const [isLoading, setIsLoading] = useState(false);
  
  const email = location.state?.email || '';
  
  const [otp, setOtp] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email) {
      toast.error('Email is missing. Please login again.');
      navigate('/login');
      return;
    }

    setIsLoading(true);
    
    try {
      const response = await fetch(`${API_BASE_URL}/user/verify-otp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ email, otp }),
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.message || 'OTP verification failed');
      }

      dispatch(setCredentials(result));
      toast.success('Login successful!');
      navigate('/dashboard');
    } catch (error: any) {
      toast.error(error.message || 'Invalid OTP');
    } finally {
      setIsLoading(false);
    }
  };

  if (!email) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-4">
        <Card className="glass w-full max-w-md">
          <CardContent className="pt-6 text-center">
            <p className="text-muted-foreground">No email found. Please login again.</p>
            <Button
              onClick={() => navigate('/login')}
              className="mt-4 gradient-primary"
            >
              Go to Login
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="w-full max-w-md"
      >
        <Card className="glass">
          <CardHeader className="text-center">
            <div className="mb-4 flex justify-center">
              <div className="rounded-full bg-primary/10 p-3">
                <Shield className="h-8 w-8 text-primary" />
              </div>
            </div>
            <Link to="/">
              <h1 className="mb-4 text-3xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                Spacedly
              </h1>
            </Link>
            <CardTitle>Verify Your Identity</CardTitle>
            <CardDescription>
              We've sent a verification code to <br />
              <span className="font-medium text-foreground">{email}</span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="otp">Verification Code</Label>
                <Input
                  id="otp"
                  type="text"
                  placeholder="Enter 6-digit code"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  maxLength={6}
                  required
                  className="text-center text-2xl tracking-widest"
                />
                <p className="text-xs text-muted-foreground text-center">
                  Code expires in 5 minutes
                </p>
              </div>

              <Button
                type="submit"
                className="w-full gradient-primary"
                disabled={isLoading || otp.length !== 6}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Verifying...
                  </>
                ) : (
                  'Verify & Login'
                )}
              </Button>
            </form>

            <div className="mt-4 text-center">
              <p className="text-sm text-muted-foreground">
                Didn't receive the code?{' '}
                <button
                  onClick={() => {
                    toast.info('Please login again to receive a new code');
                    navigate('/login');
                  }}
                  className="text-primary hover:underline"
                >
                  Login again
                </button>
              </p>
            </div>

            <div className="mt-4 text-center">
              <Link to="/login" className="text-sm text-muted-foreground hover:text-primary">
                ← Back to login
              </Link>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
};

export default VerifyOTP;
