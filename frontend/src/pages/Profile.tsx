import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { User } from 'lucide-react';
import { useAppSelector } from '@/store/hooks';

const Profile = () => {
  const user = useAppSelector((state) => state.user.profile);

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
          <div>
            <p className="text-sm text-muted-foreground">Name</p>
            <p className="text-lg font-medium">{user?.name || 'Not set'}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Email</p>
            <p className="text-lg font-medium">{user?.email || 'Not set'}</p>
          </div>
        </CardContent>
      </Card>

      <Card className="glass">
        <CardContent className="p-6 text-center text-muted-foreground">
          <p>Profile editing features coming soon!</p>
        </CardContent>
      </Card>
    </div>
  );
};

export default Profile;
