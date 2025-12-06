import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Settings as SettingsIcon, Shield, Key } from 'lucide-react';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useGetMeQuery, useToggle2FAMutation, useSetPasswordMutation } from '@/store/api/authApi';
import { toast } from 'sonner';
import { useState } from 'react';

const Settings = () => {
  const { data: userData } = useGetMeQuery(undefined);
  const [toggle2FA, { isLoading }] = useToggle2FAMutation();
  const [setPassword, { isLoading: isSettingPassword }] = useSetPasswordMutation();
  
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  
  const user = userData?.data?.user || userData?.user;
  const is2FAEnabled = user?.is_two_factor_enabled || false;

  const handle2FAToggle = async (enabled: boolean) => {
    try {
      await toggle2FA({ is_Enabled: enabled }).unwrap();
      toast.success(`Two-factor authentication ${enabled ? 'enabled' : 'disabled'}`);
    } catch (error: any) {
      toast.error(error?.data?.message || 'Failed to update 2FA settings');
    }
  };

  const handleSetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (newPassword.length < 6) {
      toast.error('Password must be at least 6 characters long');
      return;
    }
    
    if (newPassword !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    try {
      await setPassword({ password: newPassword }).unwrap();
      toast.success('Password set successfully! You can now login with email and password.');
      setNewPassword('');
      setConfirmPassword('');
      setShowPasswordForm(false);
    } catch (error: any) {
      toast.error(error?.data?.message || 'Failed to set password');
    }
  };

  // Only show password setting for OAuth users who haven't set a password yet
  const isOAuthUser = user?.auth_provider && user.auth_provider !== 'local';
  const hasPassword = user?.has_password || false;
  const canSetPassword = isOAuthUser && !hasPassword;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-3">
        <SettingsIcon className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold">Settings</h1>
          <p className="text-muted-foreground">Customize your experience</p>
        </div>
      </div>

      <Card className="glass">
        <CardHeader>
          <CardTitle>Appearance</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <Label>Theme</Label>
            <ThemeToggle />
          </div>
        </CardContent>
      </Card>

      <Card className="glass">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Security
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* OAuth Password Setting */}
          {canSetPassword && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="flex items-center gap-2">
                    <Key className="h-4 w-4" />
                    Set Password for Email Login
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    You signed up with {user?.auth_provider}. Set a password to also login with email.
                  </p>
                </div>
                {!showPasswordForm && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowPasswordForm(true)}
                  >
                    Set Password
                  </Button>
                )}
              </div>
              
              {showPasswordForm && (
                <form onSubmit={handleSetPassword} className="space-y-4 rounded-lg border p-4">
                  <div className="space-y-2">
                    <Label htmlFor="new-password">New Password</Label>
                    <Input
                      id="new-password"
                      type="password"
                      placeholder="Enter new password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      required
                      minLength={6}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="confirm-password">Confirm Password</Label>
                    <Input
                      id="confirm-password"
                      type="password"
                      placeholder="Confirm new password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      required
                      minLength={6}
                    />
                  </div>
                  
                  <div className="flex gap-2">
                    <Button
                      type="submit"
                      disabled={isSettingPassword}
                      className="flex-1"
                    >
                      {isSettingPassword ? 'Setting...' : 'Set Password'}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => {
                        setShowPasswordForm(false);
                        setNewPassword('');
                        setConfirmPassword('');
                      }}
                    >
                      Cancel
                    </Button>
                  </div>
                </form>
              )}
            </div>
          )}
          
          {/* 2FA Toggle */}
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="2fa-toggle">Two-Factor Authentication</Label>
              <p className="text-sm text-muted-foreground">
                Add an extra layer of security to your account
              </p>
            </div>
            <Switch
              id="2fa-toggle"
              checked={is2FAEnabled}
              onCheckedChange={handle2FAToggle}
              disabled={isLoading}
            />
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Settings;
