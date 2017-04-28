import requests
from bs4 import BeautifulSoup
import urlparse

def getimageurls(url):
    # url = "https://www.google.com.jm/search?q=high+quality+wallpapers&tbm=isch&tbo=u&source=univ&sa=X&ved=0ahUKEwiQjPPA4IbTAhXE1CYKHSOnDSgQsAQIFw&biw=1536&bih=744&dpr=1.25"

    result = requests.get(url)
    soup = BeautifulSoup(result.text, "lxml")

    # This will look for a meta tag with the og:image property
    og_image = (soup.find('meta', property='og:image') or
                soup.find('meta', attrs={'name': 'og:image'}))
    if og_image and og_image['content']:
        print og_image['content']
        print ''

    # This will look for a link tag with a rel attribute set to 'image_src'
    thumbnail_spec = soup.find('link', rel='image_src')
    if thumbnail_spec and thumbnail_spec['href']:
        print thumbnail_spec['href']
        print ''


    images = []
    for img in soup.findAll("img", src=True):
       images += [img["src"]]
    return images
