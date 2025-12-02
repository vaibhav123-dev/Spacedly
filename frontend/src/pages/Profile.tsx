import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { User, Mail, Calendar, Shield, Globe } from 'lucide-react';
import { useGetMeQuery } from '@/store/api/authApi';
import { Badge } from '@/components/ui/badge';
import { format } from 'date-fns';

const Profile = () => {
  const { data: userData, isLoading } = useGetMeQuery(undefined);
  
  const user = userData?.data?.user || userData?.user;

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-3">
        <User className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold">Profile</h1>
          <p className="text-muted-foreground">Manage your account information</p>
        </div>
      </div>

      <Card className="glass">
        <CardHeader>
          <CardTitle>User Information</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-3">
            <User className="h-5 w-5 text-muted-foreground" />
            <div className="flex-1">
              <p className="text-sm text-muted-foreground">Name</p>
              <p className="text-lg font-medium">{user?.name || 'Not set'}</p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            <Mail className="h-5 w-5 text-muted-foreground" />
            <div className="flex-1">
              <p className="text-sm text-muted-foreground">Email</p>
              <p className="text-lg font-medium">{user?.email || 'Not set'}</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Globe className="h-5 w-5 text-muted-foreground" />
            <div className="flex-1">
              <p className="text-sm text-muted-foreground">Authentication Provider</p>
              <Badge variant="outline" className="mt-1">
                {user?.auth_provider === 'google' ? 'Google' : 'Email/Password'}
              </Badge>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Shield className="h-5 w-5 text-muted-foreground" />
            <div className="flex-1">
              <p className="text-sm text-muted-foreground">Two-Factor Authentication</p>
              <Badge 
                variant={user?.is_two_factor_enabled ? 'default' : 'secondary'} 
                className="mt-1"
              >
                {user?.is_two_factor_enabled ? 'Enabled' : 'Disabled'}
              </Badge>
            </div>
          </div>

          {user?.createdAt && (
            <div className="flex items-center gap-3">
              <Calendar className="h-5 w-5 text-muted-foreground" />
              <div className="flex-1">
                <p className="text-sm text-muted-foreground">Member Since</p>
                <p className="text-lg font-medium">
                  {format(new Date(user.createdAt), 'MMMM d, yyyy')}
                </p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Profile;
