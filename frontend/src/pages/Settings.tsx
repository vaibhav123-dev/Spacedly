import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Settings as SettingsIcon, Shield } from 'lucide-react';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { useGetMeQuery, useToggle2FAMutation } from '@/store/api/authApi';
import { toast } from 'sonner';

const Settings = () => {
  const { data: userData } = useGetMeQuery(undefined);
  const [toggle2FA, { isLoading }] = useToggle2FAMutation();
  
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
        <CardContent>
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
