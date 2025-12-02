import { Button } from '@/components/ui/button';
import { ArrowRight, CheckCircle, Calendar, Bell, BarChart3 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';

const Landing = () => {
  const navigate = useNavigate();

  const features = [
    {
      icon: CheckCircle,
      title: 'Smart Task Management',
      description: 'Organize tasks by category and priority with intelligent reminders',
    },
    {
      icon: Calendar,
      title: 'Spaced Revision Calendar',
      description: 'Visual calendar with drag-and-drop scheduling for optimal learning',
    },
    {
      icon: Bell,
      title: 'Intelligent Reminders',
      description: 'Never miss a revision with smart, timed notifications',
    },
    {
      icon: BarChart3,
      title: 'Analytics & Insights',
      description: 'Track your progress with detailed analytics and streak tracking',
    },
  ];

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="border-b border-border">
        <nav className="container mx-auto flex items-center justify-between px-4 py-4">
          <h1 className="text-2xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
            Spacedly
          </h1>
          <div className="flex gap-4">
            <Button variant="ghost" onClick={() => navigate('/login')}>
              Login
            </Button>
            <Button onClick={() => navigate('/signup')} className="gradient-primary">
              Get Started
            </Button>
          </div>
        </nav>
      </header>

      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <h1 className="mb-6 text-5xl font-bold leading-tight md:text-6xl">
            Master Your Learning with
            <br />
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              Spaced Revision
            </span>
          </h1>
          <p className="mx-auto mb-8 max-w-2xl text-xl text-muted-foreground">
            Spacedly helps you remember more by reminding you at the perfect time.
            Build lasting knowledge with science-backed spaced repetition.
          </p>
          <div className="flex justify-center gap-4">
            <Button
              size="lg"
              onClick={() => navigate('/signup')}
              className="gradient-primary shadow-glow group"
            >
              Start Free Today
              <ArrowRight className="ml-2 h-5 w-5 transition-transform group-hover:translate-x-1" />
            </Button>
            <Button size="lg" variant="outline" onClick={() => navigate('/login')}>
              Sign In
            </Button>
          </div>
        </motion.div>
      </section>

      {/* Features Section */}
      <section className="container mx-auto px-4 py-20">
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <h2 className="mb-12 text-center text-4xl font-bold">
            Everything You Need to Excel
          </h2>
          <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-4">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: index * 0.1 }}
                viewport={{ once: true }}
                className="glass rounded-lg p-6 transition-smooth hover:shadow-glow"
              >
                <div className="mb-4 inline-block rounded-full bg-primary/10 p-3">
                  <feature.icon className="h-6 w-6 text-primary" />
                </div>
                <h3 className="mb-2 text-xl font-semibold">{feature.title}</h3>
                <p className="text-muted-foreground">{feature.description}</p>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </section>

      {/* CTA Section */}
      <section className="container mx-auto px-4 py-20">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="gradient-primary rounded-2xl p-12 text-center text-primary-foreground"
        >
          <h2 className="mb-4 text-4xl font-bold">Ready to Transform Your Learning?</h2>
          <p className="mb-8 text-xl opacity-90">
            Join thousands of learners mastering their subjects with Spacedly
          </p>
          <Button
            size="lg"
            variant="secondary"
            onClick={() => navigate('/signup')}
            className="shadow-lg"
          >
            Get Started Free
          </Button>
        </motion.div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-8">
        <div className="container mx-auto px-4 text-center text-muted-foreground">
          <p>&copy; 2024 Spacedly. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
