package com.snapdeal.servicediscovery;



import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.framework.recipes.cache.TreeCache;
import org.apache.curator.framework.recipes.cache.TreeCacheEvent;
import org.apache.curator.framework.recipes.cache.TreeCacheListener;
import org.apache.curator.retry.ExponentialBackoffRetry;
import org.apache.curator.utils.CloseableUtils;
import org.apache.curator.utils.ZKPaths;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.snapdeal.vault.CreateUser;
import com.snapdeal.vault.KeyManager;

public class ZookeeperWatcher implements Runnable{
	String root;
	String zkConnString;
	boolean done=false;
	private final Logger logger = LoggerFactory.getLogger(ZookeeperWatcher.class);
	
	public ZookeeperWatcher(String root, String zkConnString) {
		super();
		this.root = root;
		this.zkConnString = zkConnString;
	}



	public void watcher() {
		CuratorFramework client = null;
		TreeCache cache = null;
		boolean done=false;
		try {
			client = CuratorFrameworkFactory.newClient(zkConnString,
					new ExponentialBackoffRetry(1000, 3));
			client.start();
			cache = new TreeCache(client, root);
			cache.start();
			
			addListener(cache);
			
			while(!done){
				Thread.sleep(1000);
			}
			
		} catch(Exception ex){
			ex.printStackTrace();
		}finally {
			CloseableUtils.closeQuietly(cache);
			CloseableUtils.closeQuietly(client);
		}
		
	}

	
	
	private void addListener(final TreeCache cache) {
		TreeCacheListener listener = new TreeCacheListener() {

			@Override
			public void childEvent(CuratorFramework client, TreeCacheEvent event)
					throws Exception {
				String path;
				CreateUser user = new CreateUser();
				KeyManager keymanager = new KeyManager();
				switch (event.getType()) {
				case NODE_ADDED: {
					/*System.out.println("TreeNode added: "
							+ event.getData().getPath()
							+ ", value: "
							+ new String(event.getData().getData()));*/
					
					path = event.getData().getPath();
					int countslash=0;
					for(int i=0;i<path.length();i++){
						if(path.charAt(i)=='/'){
							countslash++;
						}
					}
					logger.info("New Host added:"+path);
					
					if(countslash==7){
						String clienttoken = keymanager.authenticate();
						if(user.createAppId(path,clienttoken) == 200 ){
							//Thread.sleep(1000);
							if(user.createUserId(new String(event.getData().getData()),path,clienttoken) == 200){
								logger.info("USER CREATED SUCCESSFULLY IN VAULT");
							}else{
								logger.error("ERROR in CREATING USERID IN VAULT");
							}	
						} 
						else{
							logger.error("ERROR CREATING APPID IN VAULT");
						}	
					}
					
					break;
				}
				case NODE_UPDATED: {
					/*System.out.println("TreeNode changed: "
							+ ZKPaths.getNodeFromPath(event.getData().getPath())
							+ ", value: "
							+ new String(event.getData().getData()));*/
					break;
				}
				case NODE_REMOVED: {
					/*System.out.println("TreeNode removed: "+ ZKPaths.getNodeFromPath(event.getData()
							.getPath()));*/
					break;
				}
				default:
					System.out.println("Other event: " + event.getType().name());
				}
			}

		};

		cache.getListenable().addListener(listener);
	}



	@Override
	public void run() {
		this.watcher();
		
	}

}
